#include "HotKeyStructs.h"

UINT hotkeyCounter = 0;

/*
 * Function: GetSystemModuleBase
 * -----------------------------
 * Retrieves the base address of a system module given its name.
 *
 * Parameters:
 *   moduleName - A constant reference to a UNICODE_STRING that specifies the name of the module.
 *
 * Returns:
 *   A pointer (PVOID) to the base address of the module if found;
 *   otherwise, returns nullptr.
 *
 * Reference:
 * https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo
 */

PVOID GetSystemModuleBase(
    _In_ const UNICODE_STRING& moduleName)
{
    // Get the address of the PsLoadedModuleList function
    UNICODE_STRING psLoadedModuleListName;
    RtlInitUnicodeString(&psLoadedModuleListName, L"PsLoadedModuleList");
    PLIST_ENTRY moduleList = reinterpret_cast<PLIST_ENTRY>(MmGetSystemRoutineAddress(&psLoadedModuleListName));

    if (!moduleList || IsListEmpty(moduleList))
    {
        return nullptr;
    }

    // Iterate over the module list
    for (PLIST_ENTRY pListEntry = moduleList->Flink;
        pListEntry != moduleList; pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (RtlEqualUnicodeString(&pEntry->BaseDllName, &moduleName, TRUE))
        {
            // If the module names match, return the module base address.
            return pEntry->DllBase;
        }
    }
    return nullptr;
}

/*
 * Function: GetSystemModuleBase
 * -----------------------------
 * Retrieves the PID for a process name matches the provided Unicode string.
 *
 * Parameters:
 *   processName - A constant reference to a UNICODE_STRING that specifies the name of the target process.
 *
 * Return Value:
 *   A HANDLE representing the process ID of the matching process if found; otherwise, returns nullptr.
 *
 * Reference:
 *   https://www.unknowncheats.me/forum/general-programming-and-reversing/572734-pid-process-name.html
 */

HANDLE GetPidFromProcessName(
    _In_ const UNICODE_STRING& processName)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    UNICODE_STRING funcName;

    //
    // [1] Get the address of ZwQuerySystemInformation
    //
    RtlInitUnicodeString(&funcName, L"ZwQuerySystemInformation");
    ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&funcName);
    if (!ZwQuerySystemInformation)
    {
        KdPrint(("[-] Failed to locate ZwQuerySystemInformation.\n"));
        return nullptr;
    }

    //
    // [2] Retrieve running process list using ZwQuerySystemInformation
    //

    // First call to determine the required buffer size for system process information.
    ntStatus = ZwQuerySystemInformation(SystemProcessInformation, buffer,
                                        bufferSize, &bufferSize);
    if (STATUS_INFO_LENGTH_MISMATCH != ntStatus)
    {
        KdPrint(("[-] ZwQuerySystemInformation failed to get buffer size: 0x%X\n", ntStatus));
        return nullptr;
    }

    // Allocate a buffer with the size returned.
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, POOL_TAG);
    if (!buffer)
    {
        KdPrint(("[-] ExAllocatePool2 failed to allocate buffer of size %lu.\n", bufferSize));
        return nullptr;
    }

    // Retrieve the actual process information.
    ntStatus = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(ntStatus))
    {
        KdPrint(("[-] ZwQuerySystemInformation failed: 0x%X\n", ntStatus));
        ExFreePoolWithTag(buffer, POOL_TAG);
        return nullptr;
    }

    //
    // [3] Iterate through the process list to find a matching process name.
    //
    auto pProcInfoBuffer = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
    while (pProcInfoBuffer)
    {
        // If the process has a valid image name, compare it with the provided process name.
        if (NULL != pProcInfoBuffer->ImageName.Buffer)
        {
            if (RtlCompareUnicodeString(&(pProcInfoBuffer->ImageName), &processName, TRUE) == 0)
            {
                ExFreePoolWithTag(buffer, POOL_TAG);
                return pProcInfoBuffer->ProcessId;
            }
        }
        if (0 == pProcInfoBuffer->NextEntryOffset) {
            pProcInfoBuffer = nullptr;
        }
        else
        {
            pProcInfoBuffer = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                reinterpret_cast<PUCHAR>(pProcInfoBuffer) + pProcInfoBuffer->NextEntryOffset);
        }
    }
    // Free the allocated buffer if no matching process was found.
    ExFreePoolWithTag(buffer, POOL_TAG);
    return nullptr;
}

/*
 * Function: FindIsHotKeyFunction
 * -----------------------------
 * Scans a memory region for a CALL instruction (opcode 0xE8 [32bit offset]) 
 * that likely calls the IsHotKey function. When found, it calculates the absolute address
 * of the target function using the offset.
 * Note - This function is expected to scan the "EditionIsHotkey" function.
 *
 * EditionIsHotKey function
 * 48 83 EC 28       sub     rsp, 28h
 * E8 7F 74 EE FF    call    IsHotKey
 * 33 C9             xor     ecx, ecx
 * 48 85 C0          test    rax, rax
 * 0F 95 C1          setnz   cl
 * 8B C1             mov     eax, ecx
 * 48 83 C4 28       add     rsp, 28h
 * C3                retn
 * 
 * Parameters:
 *   address - A pointer to the beginning of the memory region to scan.
 *
 * Return Value:
 *   The absolute address of the function called by the CALL instruction if found; otherwise, nullptr.
 *
 * Reference:
 *   https://eversinc33.com/posts/kernel-mode-keylogging.html
 */

PVOID
FindIsHotKeyFunction(
    _In_ const PULONG& address)
{
    USHORT i;
    PVOID isHotKeyAddr = nullptr;
    PBYTE baseAddr = (PBYTE)address;
    if (!address)
    {
        KdPrint(("[-] Invalid address\n"));
        return nullptr;
    }

    // Scan the first 30 bytes of the memory region.
    for (i = 0; i < 30; i++)
    {
        // Check if the current byte is the CALL opcode (0xE8).
        if (*(BYTE*)(baseAddr + i) == 0xE8)
        {
            INT32 offset = 0;
            // Copy the 32-bit offset located immediately after the CALL opcode.
            RtlCopyMemory(&offset, reinterpret_cast<PVOID>(baseAddr + i + 1), sizeof(offset));
            // Calculate the absolute address of the called function.
            isHotKeyAddr = (PVOID)(baseAddr + i + offset + 5);
            break;
        }
        // If a RET instruction (opcode 0xC3) is encountered, stop scanning.
        if (*(BYTE*)(baseAddr + i) == 0xC3)
        {
            break;
        }
    }
    return isHotKeyAddr;
}

/*
 * Function: ResolvegphkHashTableAddress
 * -----------------------------
 * Scans a memory region for a LEA rbx (opcode 0x48, 0x8D, 0x1D [32bit offset]) 
 * that stores the gphkHashTable address (offset). When found, it calculates the 
 * absolute address using the offset.
 * Note - This function is expected to scan the "IsHotkey" function.
 *
 * IsHotKey function
 * 48 89 5C 24 08         mov     [rsp+arg_0], rbx
 * 48 89 74 24 10         mov     [rsp+arg_8], rsi
 * 57                     push    rdi
 * 48 83 EC 50            sub     rsp, 50h
 * 0F B6 C2               movzx   eax, dl
 * 48 8D 1D 1F 8D 26 00   lea     rbx, ?gphkHashTable@@3PAPEAUtagHOTKEY@@A
 * 83 E0 7F               and     eax, 7Fh
 * 8B FA                  mov     edi, edx
 * 8B F1                  mov     esi, ecx
 * 48 8B 1C C3            mov     rbx, [rbx+rax*8]
  *
  * Parameters:
  *   address - A pointer to the beginning of the memory region to scan.
  *
  * Return Value:
  *   The absolute address of gphkHashTable if found; otherwise, nullptr.
  * 
  * Reference:
  *   https://eversinc33.com/posts/kernel-mode-keylogging.html
  */

PVOID
ResolvegphkHashTableAddress(
    _In_ const PVOID& address)
{

    USHORT i;
    PVOID gphkHashTableAddr = nullptr;
    PBYTE baseAddress = (PBYTE)address;
    if (!address)
    {
        KdPrint(("[-] Invalid address\n"));
        return nullptr;
    }

    // Scan the first 30 bytes of the memory region.
    for (i = 0; i < 30; i++)
    {
        // Check if the current byte is the LEA rbx (0x48,0x8D,0x1D)
        if ((*(BYTE*)(baseAddress + i) == 0x48) &&
            (*(BYTE*)(baseAddress + i + 1) == 0x8D) &&
            (*(BYTE*)(baseAddress + i + 2) == 0x1D))
        {
            INT32 offset = 0;
            // Copy the 32-bit offset located immediately after the LEA rbx opcode.
            RtlCopyMemory(&offset, reinterpret_cast<PVOID>(baseAddress + i + 3), sizeof(offset));
            // Calculate the absolute address
            gphkHashTableAddr = (PVOID)(baseAddress + i + offset + 7);
            break;
        }
        // If a RET instruction (opcode 0xC3) is encountered, stop scanning.
        if (*(BYTE*)(baseAddress + i) == 0xC3)
        {
            break;
        }
    }
    return gphkHashTableAddr;
}

/*
 * Function: FindgphkHashTableAddress
 * ----------------------------------
 * Attempts to resolve the address of the gphkHashTable from the Win32kfull module.
 *
 * Parameters:
 *   Win32kfullBaseAddr - A pointer to the base address of the Win32kfull module.
 *
 * Return Value:
 *   Returns the address of the gphkHashTable if successfully resolved; otherwise, returns nullptr.
 */

PVOID
FindgphkHashTableAddress(
    _In_ const PVOID& Win32kfullBaseAddr)
{

    PVOID gphkHashTable = nullptr;
    if (!Win32kfullBaseAddr)
    {
        KdPrint(("[-] Invalid Win32kfullBaseAddr\n"));
        goto Cleanup;
    }

    // [1] Retrieve the address of the "EditionIsHotKey" funtion.
    //     This exported function calls "IsHotKey" function which contains gphkHashTable
    PULONG editionIsHotKeyAddr = (PULONG)RtlFindExportedRoutineByName(Win32kfullBaseAddr, "EditionIsHotKey");
    if (!editionIsHotKeyAddr)
    {
        KdPrint(("[-] Failed to resolve EditionIsHotKey address.\n"));
        goto Cleanup;
    }

    // [2] Retrieve the address of the "IsHotKey" Function.
    PVOID isHotKeyAddr = FindIsHotKeyFunction(editionIsHotKeyAddr);
    if (!isHotKeyAddr)
    {
        KdPrint(("[-] Failed to resolve IsHotKey address.\n"));
        goto Cleanup;
    }

    // [3] Finally, resolve the address of gphkHashTable.
    gphkHashTable = ResolvegphkHashTableAddress(isHotKeyAddr);
    if (!gphkHashTable)
    {
        KdPrint(("[-] Failed to resolve gphkHashTable address.\n"));
    }
Cleanup:
    return gphkHashTable;
}


/*
 * Function: CheckHotkeyNode
 * ----------------------------------
 * Recursively checks a hotkey node.
 *
 * Parameters:
 *   hk - A pointer of HOT_KEY object.
 *
 * Reference:
 *   http://blog.blackint3.com:88/posts/2020/enum-windows-hotkey/
 */

VOID
CheckHotkeyNode(
    _In_ const PHOT_KEY& hk)
{
    if (MmIsAddressValid(hk->pNext)) {
        CheckHotkeyNode(hk->pNext);
    }

    // Check whether this is a single numeric hotkey.
    if ((hk->vk >= 0x30) && (hk->vk <= 0x39) && (hk->modifiers1 == 0))
    {
        KdPrint(("[+] hk->id: %u hk->vk: %x\n", hk->id, hk->vk));
        hotkeyCounter++;
    }
    // Check whether this is a single alphabet hotkey.
    else if ((hk->vk >= 0x41) && (hk->vk <= 0x5A) && (hk->modifiers1 == 0))
    {
        KdPrint(("[+] hk->id: %u hk->vk: %x\n", hk->id, hk->vk));
        hotkeyCounter++;
    }
    //We can also check a hotkey with modifieres such as SHIFT + A like following
    /*
    else if ((hk->vk >= 0x41) && (hk->vk <= 0x5A) && (hk->modifiers1 == MOD_SHIFT))
    {
        KdPrint(("[+] hk->id: %u hk->vk: %x\n", hk->id, hk->vk));
        hotkeyCounter++;
    }
    */
}

/*
 * Function: CheckRegisteredHotKeys
 * ----------------------------------
 * Checks the registered hotkeys from a given hash table address.
 *
 * Parameters:
 *   gphkHashTableAddr - A pointer holding the address of the hotkey hash table.
 *
 * Return Value:
 *   TRUE if it finishes scanning the hotkey table; FALSE if the provided address is invalid.
 * 
 * Reference:
 *   http://blog.blackint3.com:88/posts/2020/enum-windows-hotkey/
 */

BOOL
CheckRegisteredHotKeys(
    _In_ const PVOID& gphkHashTableAddr)
{
    if (!gphkHashTableAddr)
    {
        KdPrint(("[-] Invalid gphkHashTableAddr\n"));
        return FALSE;
    }

    // Cast the gphkHashTable address to an array of pointers.
    PVOID* tableArray = static_cast<PVOID*>(gphkHashTableAddr);
    // Iterate through the hash table entries.
    for (USHORT j = 0; j < 0x7f; j++)
    {
        PVOID item = tableArray[j];
        PHOT_KEY hk = reinterpret_cast<PHOT_KEY>(item);
        if (hk)
        {
            CheckHotkeyNode(hk);
        }
    }
    return TRUE;
}

/*
 * Function: DetectHotKeyBasedKeylogger
 * --------------------------------------
 * Scans the system's hotkey hash table to determine whether all alphanumeric keys are
 * registered as hotkeys. If 36 or more such hotkeys are found, it strongly suggests that
 * every alphanumeric key is hijacked—indicating the possible presence of a hotkey-based keylogger.
 *
 * Return Value:
 *   Returns TRUE if a keylogger is likely detected; FALSE otherwise.
 */
BOOL DetectHotKeyBasedKeylogger() {

    BOOL detected = FALSE;

    //
    // [1] Resolve Win32kfull module base address.
    // 
    UNICODE_STRING win32kfull;
    RtlInitUnicodeString(&win32kfull, L"win32kfull.sys");
    PVOID Win32kfullBaseAddr = GetSystemModuleBase(win32kfull);
    if (!Win32kfullBaseAddr)
    {
        KdPrint(("[-] Failed to get Win32kfull base address.\n"));
        return FALSE;
    }

    //
    // [2] Get EPROCESS of winlogon and attach it. 
    // 
    KAPC_STATE apc;
    PEPROCESS winlogon;
    UNICODE_STRING processName;

    RtlInitUnicodeString(&processName, L"winlogon.exe");
    HANDLE procId = GetPidFromProcessName(processName);
    if (!procId)
    {
        KdPrint(("[-] Failed to get the process id of winlogon.exe.\n"));
        return FALSE;
    }
    NTSTATUS status = PsLookupProcessByProcessId(procId, &winlogon);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[-] PsLookupProcessByProcessId failed: 0x%x.\n", status));
        return FALSE;
    }
    KeStackAttachProcess(winlogon, &apc);

    //
    // [3] Find and resolve gphkHashTable Address.
    //
    PVOID gphkHashTableAddr = FindgphkHashTableAddress(Win32kfullBaseAddr);
    if (!gphkHashTableAddr)
    {
        KdPrint(("[-] Failed to resolve gphkHashTable address\n"));
        goto Cleanup;
    }

    //
    // [4] Scan the hotkey table to count how many single alphanumeric hotkeys are registered.
    //     If 36 or more are found, it implies that every alphanumeric key is hijacked,
    //     which strongly suggests the presence of a hotkey-based keylogger.
    //
    if (CheckRegisteredHotKeys(gphkHashTableAddr) && hotkeyCounter >= 36)
    {
        detected = TRUE;
        goto Cleanup;
    }

Cleanup:
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(winlogon);
    return detected;
}

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrint(("[+] Unloading the driver..\n"));
}

extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    // Set the unload routine
    DriverObject->DriverUnload = DriverUnload;

    KdPrint(("[+] Start Hotkey-based keylogger detector!"));

    if (DetectHotKeyBasedKeylogger())
    {
        KdPrint(("============================================\n"));
        KdPrint(("          [** SECURITY ALERT **]            \n"));
        KdPrint(("      Hotkey-based keylogger detected!      \n"));
        KdPrint(("============================================\n"));
    }
    else
    {
        KdPrint(("[+] Finished the scan. Nothing detected!\n"));
    }

    return STATUS_SUCCESS;
}