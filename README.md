# esxi_ks_iso
Generate Bootable esxi iso with baked kickstart scripts natively in powershell

No need for mkisofs here or openssl passwd here.

try the example, make sure to have the -ISOPath set your actual path to esxi install media.

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
### Reuse configuration

Because everything is written with Objects its easy to reuse configurations. Include Out-Json | Out-File "x\y.json" -encoding ascii at the end of your script. And to reuse it, do the following.
```
$ConfigJson = cat .\Current-config.json | ConvertFrom-Json
$vSphere = [vSphere]::new()
$vSphere = $ConfigJson
Set-Paths -ISOPath "$PSScriptRoot\VMware-VMvisor-Installer-6.7.0.update03-14320388.x86_64.iso" -WorkDirectory "$PSScriptRoot\source" -OutputDirectory "$PSScriptRoot\ISO"
Mount-ISO 
Set-SourceFiles
foreach ($VMH in (Get-VMH -Hostname "*").Hostname)
{
    New-KsScript -Hostname $VMH
    Write-ISO -ISOName $VMH

}
Dismount-DiskImage -DevicePath $ISO.DevicePath | Out-Null
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

rootpw --iscrypted $1$sLkLgT9g$Ivx5BmS3T2.JID6oiO8gl.
network --bootproto=static --vlanid=99  --ip=192.168.88.120 --netmask=255.255.255.0 --gateway=192.168.88.1 --nameserver=192.168.88.10,192.168.10.11 --hostname=ESXi03.test.local

install --firstdisk=local --overwritevmfs

keyboard 'Swedish'

reboot

%firstboot --interpreter=busybox

esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1
esxcli system settings advanced set -o /UserVars/HostClientCEIPOptIn -i 2
esxcli network ip set --ipv6-enabled=false

#Standard vSwitches
esxcli network vswitch standard add --vswitch-name=vSwitch1

#Uplinks
esxcli network vswitch standard uplink add --uplink-name=vmnic4  --vswitch-name=vSwitch1
esxcli network vswitch standard uplink add --uplink-name=vmnic5  --vswitch-name=vSwitch1

#PortGroups
esxcli network vswitch standard portgroup add --portgroup-name=DC --vswitch-name=vSwitch1
esxcli network vswitch standard portgroup set --portgroup-name=DC --vlan-id=10
esxcli network vswitch standard portgroup add --portgroup-name=VCSA --vswitch-name=vSwitch1
esxcli network vswitch standard portgroup set --portgroup-name=VCSA --vlan-id=40

#Enable SSH and the ESXi Shell
vim-cmd hostsvc/enable_ssh
vim-cmd hostsvc/start_ssh
vim-cmd hostsvc/enable_esx_shell
vim-cmd hostsvc/start_esx_shell

### Add NTP Server addresses
echo "server 10.10.10.8" >> /etc/ntp.conf;
echo "server 10.10.11.8" >> /etc/ntp.conf;
esxcli network firewall ruleset set --enabled=true --ruleset-id=ntpClient
/sbin/chkconfig ntpd on;
#Reboot to persist changes
esxcli system shutdown reboot -d 15 -r "rebooting after ESXi host configuration"
```
