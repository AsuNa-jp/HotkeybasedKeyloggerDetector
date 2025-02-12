# Hotkey-based Keylogger Detector

## Introduction
This project, Hotkey-based Keylogger Detector, is a Windows kernel-mode driver designed to identify potential hotkey-based keyloggers that hijack/records all alphanumeric keys via system hotkeys.
The driver inspects the win32kfull.sys module, resolve the global hotkey table (gphkHashTable) address, and checks the registered hotkeys. 

## Disclamer

* This driver is provided for educational and testing purposes only.
* This driver has been tested only on Windows 10 version 22H2 (OS Build 19045.5487). It has not been tested on other versions, so it may not work properly on different Windows builds.
* Use at Your Own Risk: Running this driver is entirely at your own risk. I disclaim all responsibility for any consequences, damages, or disruptions resulting from the use of this driver.
 
## License
This project is released under the MIT License. See the LICENSE file for details.