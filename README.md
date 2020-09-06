# esxi_ks_iso
Generate Bootable esxi iso with baked kickstart scripts natively in powershell

No need for mkisofs here :)
try the example, make sure to have the -ISOPath on row 19 set your actual path to esxi install media.

If you want to make changes and include more options in the kickstart script, look at the New-KsScript function in ks_functions.ps1
