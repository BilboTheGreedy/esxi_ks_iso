# esxi_ks_iso
Generate Bootable esxi iso with baked kickstart scripts natively in powershell

No need for mkisofs here or openssl passwd here.

The big part of what makes this script different from others around on the internet is the use of c# code inside powershell to do what mkisofs and openssl has done. That is creating the bootable ISO (mkisofs style) and generate linux crypt hash with $id$salt$hash (openssl passwd -6 -salt xyz). 

Take a look at the functions Get-CryptHash and Write-ISO. Feel free to rip them out of ks_functions to create your own. You may need to make adjustment to Write-ISO depending on what media you intend to create. For my case its just for ESXi.

try the example, make sure to have the -ISOPath set your actual path to esxi install media.

The only thing thats bad... or not so good (depending on how you look at it) is the staticly assigned variable called $vSphere. You have to assign that if you intend to manually instantiate the [vSphere] object and access the Get/Set functions in ks_functions.ps1 and some other functions. It all depends Get-VMH function basically.
Other then that... rock on!

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
$vSphere = cat .\Current-config.json | ConvertFrom-Json
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

rootpw --iscrypted $6$8rC8iNhKuYSx1Tlq$SVIQQ2twH1foSWeR4uTb4sOI.1YC2od5mZguPP0xM7..8RM2/T9dVf0eu7l/gSc4HyHQW66dvkQPpusK441Ib0
network --bootproto=static --vlanid=99  --ip=192.168.88.120 --netmask=255.255.255.0 --gateway=192.168.88.1 --nameserver=192.168.88.10,192.168.10.11 --hostname=ESXi01.test.local

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
esxcli network vswitch standard uplink add --uplink-name=vmnic1  --vswitch-name=vSwitch0
esxcli network vswitch standard uplink add --uplink-name=vmnic4  --vswitch-name=vSwitch1
esxcli network vswitch standard uplink add --uplink-name=vmnic5  --vswitch-name=vSwitch1

#PortGroups
esxcli network vswitch standard portgroup add --portgroup-name=Ex-Mgmt --vswitch-name=vSwitch0
esxcli network vswitch standard portgroup set --portgroup-name=Ex-Mgmt --vlan-id=10
esxcli network vswitch standard portgroup add --portgroup-name=DC --vswitch-name=vSwitch1
esxcli network vswitch standard portgroup set --portgroup-name=DC --vlan-id=10
esxcli network vswitch standard portgroup add --portgroup-name=VCSA --vswitch-name=vSwitch1
esxcli network vswitch standard portgroup set --portgroup-name=VCSA --vlan-id=40

#Enable SSH and the ESXi Shell
vim-cmd hostsvc/enable_ssh
vim-cmd hostsvc/start_ssh
vim-cmd hostsvc/enable_esx_shell
vim-cmd hostsvc/start_esx_shell
#Syslog
esxcli system syslog config set --loghost='TCP://10.10.11.20:514'
esxcli system syslog reload

### Add NTP Server addresses
echo "server 10.10.10.8" >> /etc/ntp.conf;
echo "server 10.10.11.8" >> /etc/ntp.conf;
esxcli network firewall ruleset set --enabled=true --ruleset-id=ntpClient
/sbin/chkconfig ntpd on;
#SSLCertificate
echo -e '-----BEGIN CERTIFICATE-----\nMIIEKzCCAxOgAwIBAgIJAPFpMPwZvPgwMA0GCSqGSIb3DQEBCwUAMIGVMQswCQYD\nVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/IsZAEZ\nFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFzAVBgNV\nBAoMDnBob3Rvbi1tYWNoaW5lMRswGQYDVQQLDBJWTXdhcmUgRW5naW5lZXJpbmcw\nHhcNMjAwOTA4MDI0NjM3WhcNMjUwOTA4MDI0NjM3WjCBnTELMAkGA1UEBhMCVVMx\nEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVBhbG8gQWx0bzEPMA0GA1UE\nCgwGVk13YXJlMRswGQYDVQQLDBJWTXdhcmUgRW5naW5lZXJpbmcxFzAVBgNVBAMM\nDjE5Mi4xNjguODguMTk4MR4wHAYJKoZIhvcNAQkBFg92bWNhQHZtd2FyZS5jb20w\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeigFyofZuPCrHePvC3kSh\niLYQo6eJCC61b9kiZPtP9v7AhnQ5musClRVn8M4YYcK1qid6m9VirDg/68vAXQnK\njn3WyHCO3juV+mLAKA4XZnqfCJt+AbVCkykm97OUtlq4FVDCwsd4uEfNdq3SXUqW\nJMiYAlyayoxTzb/wYZjhvelEMhikapSVPBiqzimjnwTPzLKiQmlG2gjfohtdjnPh\nWOsY+Lc18IgcPRxjsaBF+mwhz5YJuyNFszfTU4XJAAd/w13QcYgxcW8Z9Q40yOSA\nnySn986zOvvjSlWBt7tSTdlpn3PPpbXhBUu5xou5RGsvq90/TwXwbLXaAyEcvbMD\nAgMBAAGjdDByMA8GA1UdEQQIMAaHBMCoWMYwHwYDVR0jBBgwFoAUFBo5FezvURT/\nsxuymK/GAoazVHAwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzAChiJodHRwczov\nLzE5Mi4xNjguODguMjAxL2FmZC92ZWNzL2NhMA0GCSqGSIb3DQEBCwUAA4IBAQCN\nTy3dtIFVWXEp1+12zbHalCQa6CD7zMM20158MBjCLN1dCZ0RejjzGb6pv0AidiZa\nGTOhmXAhZoTIvA70ju9cDXCiGxWurychdLXjz+HakT3DASY7C7ticf+L9qyuRj3L\ndoDssl1BAtEKf9LukUSPxweeI6IfsMbS+/zk4+LSk61Xz4DIuB3UJYZEhIahiLYV\nj31W7bns/0ye5Nikc/M0jNTirbO2Zu+YD3wOgTao+r/mBqQHT6jd0UriFb83a6o+\nyaf5cW4/VXDeV7AP+Mf37sOu7vJ2e8IeVwS+a+Q7WLVvxl86noXRUFPxMI/JqFmt\nIWok47Kb2e/euRJHcJ7e\n-----END CERTIFICATE-----' > /etc/vmware/ssl/rui.crt
echo -e '-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCeigFyofZuPCrH\nePvC3kShiLYQo6eJCC61b9kiZPtP9v7AhnQ5musClRVn8M4YYcK1qid6m9VirDg/\n68vAXQnKjn3WyHCO3juV+mLAKA4XZnqfCJt+AbVCkykm97OUtlq4FVDCwsd4uEfN\ndq3SXUqWJMiYAlyayoxTzb/wYZjhvelEMhikapSVPBiqzimjnwTPzLKiQmlG2gjf\nohtdjnPhWOsY+Lc18IgcPRxjsaBF+mwhz5YJuyNFszfTU4XJAAd/w13QcYgxcW8Z\n9Q40yOSAnySn986zOvvjSlWBt7tSTdlpn3PPpbXhBUu5xou5RGsvq90/TwXwbLXa\nAyEcvbMDAgMBAAECggEAJrKvCcko+t1q38fTREy22esh7cvUsCk0JYuIp9GYWnuC\n0YHASvNanAXB9N4doGv0eB1xh4cUPgKltEydLnZHVo8TfmLsvqLWTpSQmDDux513\nHuyd79MA6KA9MkrSJeGhIT/qt6+NuxTYSfnHEgs9koqmABzLd+kq+aXGTSm1hJxR\nQ1K52ZPjT5kKXmV4sckAgl2YP33uQxAmGXUxEVkUr6mkTfxIHVsQjteIza7QBiWe\nbvtxVIcppI/u8dHMtGp9crD8e1fjoSbOjeC0kBnQq6bk6o2ta1BJ7Wo/UsgaBTH5\nNCjPmk+n0adJErYyaw/6XIo+2PdchiWD7swD9ZRasQKBgQDJzOgPwa+LJeSpClab\n9Q2dNxAkiau7hV0m1UfK9rIycG57w9ppP0f0AejLaQrSLJhp00MkdpSbVK20E4o7\nkzyZoz8rkZSZivF+X/rDmMxE2lTPC8P7CafXXriVK4Oo92iox0aFB+sroMqAguAk\ndSpm/v+9GzKcoxCDlcQOpqBZ+wKBgQDJHpnKeBc/eCM4Amht3SQ+VcMnjCS1lNU3\niOZdKd7dEwlzAM4gvq1ZSxbKW794a3Oy9E9GcnsCFK7ZrFjDr3J0xZO/mEQOVe8F\nmXSYZyu9eMC3LF0t0s2dHwcKn0hFSbEwmZwJgNTMg64+a4uqDvMGue+3TVC7ubtZ\nUy2RmIAEmQKBgDAYAJp4u6B7CHLs/tUuYu88B0Hd+aq4TwoJPJH3l2KD/yDJ/Yyl\nwz05E0UfJLAQZsaZzd+rzyDx3nATVBd8sK2hBVYZ3QN25LUMpNPm34/tRNcPY8a5\nd2HRtkX+1+L2C+Bllb3wtDByorBcAJVPwypGzaZBDB/ekPn7QH2JYp/vAoGAdw3J\nRiR+xpCMcJxkSxzMVqYYBzIbjO3UpbJBg8bEaaPaRRyl6JZXMXOUwyc6mcMp0zZy\nMyaTkHDD7JDsXrJeE6fdxV4Sc1YFTxA/B/SS3O89TXFSm0ydcLQsS+psMq/j1vwn\ndSyxS3trywGIxJti24l30M9Qyj+xGrh1UimvJokCgYB970G2TgXbDKkIgSVDIasS\nb40av78BPyNxyufoEuw3+KLlm2wazZG2nvO4wHIfPcqLpmyqVIdtTnMZJZwxXVc2\nrJCnxnavmgX54bZr9QmzI0W1arsH9nFWvx5olnvHuYxkfWpEVHYQbPKWLV6DKJyw\nGKmbNUDz9Yu/zVqB1q7lSg==\n-----END PRIVATE KEY-----' > /etc/vmware/ssl/rui.key
services.sh restart

#Welcome Message
esxcli system welcomemsg set  -m 'This is a very secure system. You should probably not attempt to sign in.
matter of fact you are not priviliged to access the system

The SysAdmins'

#Enter Maintenance Mode
esxcli system maintenanceMode set -e true -t 60
#Reboot to persist changes
esxcli system shutdown reboot -d 15 -r "rebooting after ESXi host configuration"

```
