# VmwareHardenedLoader
Vmware Hardened VM detection mitigation loader

## First Step: Add following settings into .vmx

```
hypervisor.cpuid.v0 = "FALSE"
board-id.reflectHost = "TRUE"
hw.model.reflectHost = "TRUE"
serialNumber.reflectHost = "TRUE"
smbios.reflectHost = "TRUE"
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
```

## Second Step: Load vmloader.sys in vm guest
open command prompt as System Administrator, use the following commands

```
sc create vmloader binPath= "\??\c:\vmloader.sys" type= "kernel"
sc start vmloader
```

c:\vmloader.sys could be whatever you want.

when you no longer need the mitigation, use
```
sc stop vmloader
sc delete vmloader
```
to unload the driver.
