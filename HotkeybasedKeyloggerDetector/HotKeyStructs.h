#pragma once

#ifndef HOTKEY_STRUCTS_H
#define HOTKEY_STRUCTS_H

#include <ntifs.h>
#include <ntimage.h>
#include <ntddk.h>
#include <ntdef.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <wdm.h>

#define POOL_TAG 'HotK'
#define MOD_ALT         0x0001
#define MOD_CONTROL     0x0002
#define MOD_SHIFT       0x0004
#define MOD_WIN         0x0008

typedef PVOID PWND;
typedef UINT64 PADDING64;
typedef UINT32 PADDING32;
typedef struct _THREADINFO {
    PETHREAD thread;
} *PTHREADINFO;

typedef struct _WNDINFO {
    HWND wnd;
} *PWNDINFO;

typedef struct _HOT_KEY {
    PTHREADINFO thdinfo;
    PVOID callback;
    PWNDINFO wndinfo;
    UINT16 modifiers1;		//eg:MOD_CONTROL(0x0002)
    UINT16 modifiers2;		//eg:MOD_NOREPEAT(0x4000)
    UINT32 vk;
    UINT32 id;
#ifdef _AMD64_
    PADDING32 pad;
#endif
    struct _HOT_KEY* pNext;
} HOT_KEY, * PHOT_KEY;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


EXTERN_C PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);
typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

#endif // HOTKEY_STRUCTS_H