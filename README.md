# VmwareHardenedLoader
Vmware Hardened VM detection mitigation loader

For now, only Windows (vista~win10) x64 guests are supported.

It get vmware guest undetected by VMProtect 3.2, Safengine and Themida (anti-vm feature).

## What it does

the VmLoader driver patches SystemFirmwareTable at runtime, it removes all detectable signatures like "VMware" "Virtual" "VMWARE".

## Warning

Do not install vmtools, it will ruin everything!

use TeamViewer / AnyDesk / mstsc / VNC viewer instead!

## 1st Step: Add following settings into .vmx

```
hypervisor.cpuid.v0 = "FALSE"
board-id.reflectHost = "TRUE"
hw.model.reflectHost = "TRUE"
serialNumber.reflectHost = "TRUE"
smbios.reflectHost = "TRUE"
SMBIOS.noOEMStrings = "TRUE"
isolation.tools.getPtrLocation.disable = "TRUE"
isolation.tools.setPtrLocation.disable = "TRUE"
isolation.tools.setVersion.disable = "TRUE"
isolation.tools.getVersion.disable = "TRUE"
monitor_control.disable_directexec = "TRUE"
monitor_control.disable_chksimd = "TRUE"
monitor_control.disable_ntreloc = "TRUE"
monitor_control.disable_selfmod = "TRUE"
monitor_control.disable_reloc = "TRUE"
monitor_control.disable_btinout = "TRUE"
monitor_control.disable_btmemspace = "TRUE"
monitor_control.disable_btpriv = "TRUE"
monitor_control.disable_btseg = "TRUE"
monitor_control.restrict_backdoor = "TRUE"
```

If you have a SCSI virtual disk at scsi0 slot (first slot) as your system drive, remember add

```
scsi0:0.productID = "Whatever you want"
scsi0:0.vendorID = "Whatever you want"
```

I use
```
scsi0:0.productID = "Tencent SSD"
scsi0:0.vendorID = "Tencent"
```

## 2nd Step: Modify MAC address

Modify guest's MAC address to whatever except below:
```
	TCHAR *szMac[][2] = {
		{ _T("\x00\x05\x69"), _T("00:05:69") }, // VMWare, Inc.
		{ _T("\x00\x0C\x29"), _T("00:0c:29") }, // VMWare, Inc.
		{ _T("\x00\x1C\x14"), _T("00:1C:14") }, // VMWare, Inc.
		{ _T("\x00\x50\x56"), _T("00:50:56") },	// VMWare, Inc.
	};
```

![mac](https://github.com/hzqst/VmwareHardenedLoader/raw/master/img/4.png)

You could add

```
ethernet0.address = "Some random mac address"
```
into vmx file instead of modifying MAC address in vmware GUI

I use

```
ethernet0.address = "00:11:56:20:D2:E8"
```

## 3rd Step: Load vmloader.sys in vm guest

put vmloader.sys at C:\

open command prompt with Administrator Priviledge, use the following commands

```
sc create vmloader binPath= "\??\c:\vmloader.sys" type= "kernel" start="system"
sc start vmloader
```

`start="system"` is optional. if you want the driver to be loaded automatically when system start, add this to the command.

If an error occurs when start service, use DbgView to capture kernel debug output. you can post an issue with DbgView output information and   with your ntoskrnl.exe attached.

If no error occurs, then everything works fine.

you could put "vmloader.sys" wherever you want, except vmware shared folders.

when you no longer need the mitigation, use
```
sc stop vmloader
sc delete vmloader
```
to unload the driver.

## 4th Step: Load hidden.sys in vm guest and run HiddenTests (optional)

### Only necessary when registry keys are detected.

put hidden.sys at C:\

open command prompt with Administrator Priviledge, use the following commands

```
sc create hidden binPath= "\??\c:\hidden.sys" type= "kernel" start="system"
sc start hidden
```

`start="system"` is optional. if you want the driver to be loaded automatically when system start, add this to the command.

when you no longer need the mitigation, use
```
sc stop hidden
sc delete hidden
```
to unload the driver.

Then run HiddenTests.exe with Administrator Priviledge (which could be placed wherever you want).

When you see "successful!!", it means it's all ok.

## Showcase

Vmware guest win8.1 x64 with VMProtect 3.2 packed program (anti-vm option enabled)

![before](https://github.com/hzqst/VmwareHardenedLoader/raw/master/img/1.png)
![sigs](https://github.com/hzqst/VmwareHardenedLoader/raw/master/img/2.png)
![after](https://github.com/hzqst/VmwareHardenedLoader/raw/master/img/3.png)

## License
This software is released under the MIT License, see LICENSE.

Some util procedures are from https://github.com/tandasat/HyperPlatform

https://github.com/aquynh/capstone is used to disasm ntoskrnl code.

## TODO
~~Some registry keys are supposed to be hidden, like~~ NOW MITIGATED
![reg](https://github.com/hzqst/VmwareHardenedLoader/raw/master/img/5.png)

~~For now you have to delete those keys to bypass some shitty malwares' anti-vm check.~~

~~vmware SCSI virtual disk is also a detection vector, which could be hidden by installing a minifilter to take control of IRP_InternalIoctl that passed to disk device drivers.~~ NOW MITIGATED

vmware virtual graphic card information could be detected by querying DXGI interface, which could be modified by editing graphic driver files.
