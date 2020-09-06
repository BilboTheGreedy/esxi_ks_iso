# esxi_ks_iso
Generate Bootable esxi iso with baked kickstart scripts natively in powershell

No need for mkisofs here :)
try the example, make sure to have the -ISOPath on row 25 set your actual path to esxi install media.

If you want to make changes and include more options in the kickstart script, look at the New-KsScript function in ks_functions.ps1

Expected result from running Example.ps1
```
PS C:\projects\ks_functions> .\Example.ps1
Mounting ISO: C:\projects\ks_functions\VMware-VMvisor-Installer-201912001-15160138.x86_64.iso
Generating Kickstart script for ESXi01.test.local
Writing ISO file C:\projects\ks_functions\ISO\ESXi01.test.local
Generating Kickstart script for ESXi02.test.local
Writing ISO file C:\projects\ks_functions\ISO\ESXi02.test.local
Generating Kickstart script for ESXi03.test.local
Writing ISO file C:\projects\ks_functions\ISO\ESXi03.test.local
Done :)
```
