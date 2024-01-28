# Notes on installing crDroid on Redmi Note 8 Pro

My Redmi Note 8 Pro having reached its [EOL](https://trust.mi.com/misrc/updates/phone), I decided to recycle it with [crDroid](https://crdroid.net/).
This pages aims to summarize the notes taken during the process.

The initial MIUI ROM was at version 12.5.8.RGGMIXM.

## Download platform-tools
The main tool to interact with [ADB](https://en.wikipedia.org/wiki/Android_Debug_Bridge) and [Fastboot](https://en.wikipedia.org/wiki/Fastboot) is platform-tools. It consists in a [zip file](https://developer.android.com/tools/releases/platform-tools) that can be downloaded and extracted anywhere and contains the binaries `adb.exe` and `fastboot.exe`

## Unlock OEM
To prevent accidental operations, MIUI locks the bootloader. An official software is provided [here](https://en.miui.com/unlock/download_en.html). However it requires an account creation.
Unlocking the bootloader is also possible through a different way, using USB Driver Development kit (UsbDk) and MTK Client.

  - download and install `.msi` file from [UsbDk release](https://github.com/daynix/UsbDk)
  - download and install [MTK Client python requirements](https://github.com/bkerler/mtkclient)
  - run `python mtk da seccfg unlock`
  - put the device on recovery mode: stop device, hold vol+ and vol- while connecting cable, hold until output on screen
  - disconnect device

## Install Fastboot driver on computer
The next step is to prepare the computer to be able to talk with the phone Fastboot using the appropriate drivers.

  - download the [official driver](http://bigota.d.miui.com/tools/xiaomi_usb_driver.rar)
  - however the driver is not signed, so Driver Signature Enforcement (DSE) needs to be disabled via either:
    - Test Mode: admin powershell, then `bcdedit /set TESTSIGNING ON`, then restart. You will be in test mode. To disable `bcdedit /set TESTSIGNING OFF`
    - Disable DSE at boot: settings, update/security, recovery, advanced startup. Troubleshoot > Advanced options > Startup Settings and click the Restart. Choose option 7

## Disabling AVB
The phone [Android Verified Boot or dm-verity](https://source.android.com/docs/security/features/verifiedboot/dm-verity) also needs to be disabled to install custom images. For that the `vbmeta.img` file is needed and will be used later.

  - download [stock rom](https://cdn-ota.azureedge.net/V12.5.8.0.RGGMIXM/miui_BEGONIAGlobal_V12.5.8.0.RGGMIXM_db66dbc998_11.0.zip)
  - unzip, get `vbmeta.img`

## Install TWRP recovery
The next step is to override the official recovery software with a custom one, namely [Team Win Recovery Project](https://twrp.me/)

  - download the [recovery image for this phone model](https://dl.twrp.me/begonia/)
  - Reboot phone to bootloader `.\adb.exe reboot bootloader`
  - Flash the recovery with the TWRP one `.\fastboot.exe flash recovery twrp.img`
  - Disable Android Verified Boot `.\fastboot.exe --disable-verity --disable-verification flash vbmeta vbmeta.img`
  - Reboot to the newly flashed recovery `.\fastboot.exe reboot recovery`

## Install cDroid Android14
Before installing a custom ROM, MIUI needs to be cleaned up, and the partition formated

  - from TWRP recovery: wipe -> system, vendor, cache, dalvik, data
  - from TWRP recovery: wipe -> format
  - Download crDroid [latest version for this phone model](https://onboardcloud.dl.sourceforge.net/project/crdroid/begonia/10.x/crDroidAndroid-14.0-20240112-begonia-v10.1.zip)
  - Upload it to the cleaned partition `adb push cdroid.zip /sdcard/`
  - From TWRP: install that uploaded zip

## Install Nikgapps for Google Play
crDroid doesn't come with Google applications by default. It can be added later on, but needs a fresh installation.

  - Go to [NikGApps](https://nikgapps.com/downloads), and chose the appropriate package (e.g. Android 14 is U, then from Release chose the [one you prefer](https://onboardcloud.dl.sourceforge.net/project/nikgapps/Config-Releases/NikGapps-U/13-Jan-2024/NikGapps-Ccrlll-arm64-14-20240113.zip))
  - Boot to recovery, for instance from crDroid menu
  - Use TWRP to wipe and format data. This removes encryption and allows to upload NikGApps zip file
  - Upload the zip file `adb push nikgapps.zip sdcard`
  - Use TWRP to install the .zip uploaded
  - reboot to system
