# Hotkey-based Keylogger Detector

## Introduction
Hotkey-based Keylogger Detector is a Windows kernel-mode driver designed to detect hotkey-based keyloggers that hijack and record keystrokes using system hotkeys (RegisterHotKey API). To detect such keyloggers, the driver scans the win32kfull.sys module, resolves the address of the global hotkey table (gphkHashTable), and then checks the registered hotkeys.

## Usage

To install this driver, you must first enable test mode; please do so at your own risk.
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option

* **Install the driver (Open the Command Prompt as Administrator)**
```
sc create HotkeybasedKeyloggerDetector type=kernel start=demand binPath="C:<path_to_driver>\HotkeybasedKeyloggerDetector.sys"
sc start HotkeybasedKeyloggerDetector
```

* **Uninstall the driver**
```
sc stop HotkeybasedKeyloggerDetector
sc delete HotkeybasedKeyloggerDetector
```

* **Demo Video**

This demo showcases how this detection tool detects [Hotkeyz](https://github.com/yo-yo-yo-jbo/hotkeyz), a proof-of-concept hotkey-based keylogger created by [Jonathan Bar Or](https://jonathanbaror.com/)

https://github.com/user-attachments/assets/4eacaa4e-6d6d-4014-ae4c-b1c1c7d8fd2e

(To view log messages in [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview), you need to build the driver in "Debug" mode.)

## Disclamer

* This driver is provided for educational and testing purposes only.
* This driver has been tested only on Windows 10 version 22H2 (OS Build 19045.5487). It has not been tested on other versions, so it may not work properly on different Windows builds.
* Use at Your Own Risk: Running this driver is entirely at your own risk. I disclaim all responsibility for any consequences, damages, or disruptions resulting from the use of this driver.
 
## License
This project is released under the MIT License. See the LICENSE file for details.

## Acknowledgement
I would like to express my heartfelt gratitude to [Jonathan Bar Or](https://jonathanbaror.com/) for teaching me about hotkey-based keylogging techniques and, moreover, for kindly sharing [Hotkeyz](https://github.com/yo-yo-yo-jbo/hotkeyz), a proof-of-concept for hotkey-based keyloggers.
