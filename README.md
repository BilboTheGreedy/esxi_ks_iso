# esxi_ks_iso
Generate Bootable esxi iso with baked kickstart scripts natively in powershell

No need for mkisofs here :)
No need for openssl passwd here :)
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
### linux Crypt password hashing
```
PS C:\projects\ks_functions> ($vsphere.hosts | select password).password
Hashed                                                                                                     Algorithm PlainText
------                                                                                                     --------- ---------
$6$5rjHimqYHvtJ9cb.$X3OKBTNAPEpsbB37ocOtbaazFqxsFR/R/9FxFXtA0rZY3BT4HyKT.EgTI7voEeqHUl1BO6v8jkNDHXUoRpcHQ0 SHA512    SuperSecret1
$5$e53X/oDaa/JqO7VP$AXcRism7LxZ16OrPE3NlXlO8zmgLxJSR.fTfbT49CD7                                            SHA256    SuperSecret2
$1$Y2MFiAzF$R2vXRLnjWNKL4rZgspDkQ0                                                                         MD5       SuperSecret3

```

## Example of a generated kickstart script
```
accepteula

rootpw --iscrypted $1$BLioqtpM$4dxV17Pvt5eIs1ZihM.9Z1
network --bootproto=static --vlanid=99  --ip=192.168.88.120 --netmask=255.255.255.0 --gateway=192.168.88.1 --nameserver=192.168.88.10,192.168.10.11 --hostname=ESXi03.test.local

install --firstdisk=local --overwritevmfs

keyboard 'Swedish'

reboot

%firstboot --interpreter=busybox

#Standard vSwitches
esxcli network vswitch standard add --vswitch-name=vSwitch1

#Uplinks
esxcli network vswitch standard uplink add --uplink-name=vmnic4  --vswitch-name=vSwitch1
esxcli network vswitch standard uplink add --uplink-name=vmnic5  --vswitch-name=vSwitch1

#PortGroups
esxcli network vswitch standard portgroup add --portgroup-name=VCSA --vswitch-name=vSwitch1
esxcli network vswitch standard portgroup set --portgroup-name=VCSA --vlan-id=40

#Enable SSH and the ESXi Shell
vim-cmd hostsvc/enable_ssh
vim-cmd hostsvc/start_ssh
vim-cmd hostsvc/enable_esx_shell
vim-cmd hostsvc/start_esx_shell
esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1
```
