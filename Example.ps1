. .\ks_functions.ps1
#Something for a Welcome Message
$Msg= "This is a very secure system. You should probably not attempt to sign in.
matter of fact you are not privileged to access the system

The SysAdmins"

$VMHost = Add-VMH -Hostname "ESXi01.test.local"
$VMHost | Set-RootPW -PlainText SuperSecret1 -Algorithm SHA512
$VMHost | Set-ManagementNetwork -IPAddress 192.168.88.120 -NetworkMask 255.255.255.0 -Gateway 192.168.88.1 -VlanId 99 -Nameservers 192.168.88.10,192.168.10.11
$VMHost | Add-NTPSource -NTPSource 10.10.10.8
$VMHost | Add-NTPSource -NTPSource 10.10.11.8
$VMHost | Set-WelcomeMsg -WelcomeMsg $Msg
$VMHost | Set-Syslog -Address 10.10.11.20 -Port 514 -Protocol TCP
$VMHost | Set-SSLCertificate -CertPath .\Certificate\ESXi01Cert.crt -KeyPath .\Certificate\ESXi01Cert.Key
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch0 -ModifyExisting $True
$vSwitch | Add-NetworkAdapter -vmnic vmnic1
$vSwitch | Add-PortGroup -Name Ex-Mgmt -VlanId 10
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch1 
$vSwitch | Add-NetworkAdapter -vmnic vmnic4
$vSwitch | Add-NetworkAdapter -vmnic vmnic5
$vSwitch | Add-PortGroup -Name DC -VlanId 10
$vSwitch | Add-PortGroup -Name VCSA -VlanId 40

$VMHost = Add-VMH -Hostname "ESXi02.test.local"
$VMHost | Set-RootPW -PlainText SuperSecret2 -Algorithm SHA256
$VMHost | Set-ManagementNetwork -IPAddress 192.168.88.120 -NetworkMask 255.255.255.0 -Gateway 192.168.88.1 -VlanId 99 -Nameservers 192.168.88.10,192.168.10.11
$VMHost | Add-NTPSource -NTPSource 10.10.10.8
$VMHost | Add-NTPSource -NTPSource 10.10.11.8
$VMHost | Set-WelcomeMsg -WelcomeMsg $Msg
$VMHost | Set-Syslog -Address 10.10.11.20 -Port 514 -Protocol TCP
$VMHost | Set-SSLCertificate -CertPath .\Certificate\ESXi02Cert.crt -KeyPath .\Certificate\ESXi02Cert.Key
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch1 
$vSwitch | Add-NetworkAdapter -vmnic vmnic4
$vSwitch | Add-NetworkAdapter -vmnic vmnic5
$vSwitch | Add-PortGroup -Name DC -VlanId 10
$vSwitch | Add-PortGroup -Name VCSA -VlanId 40
$VMHost = Add-VMH -Hostname "ESXi03.test.local"

$VMHost | Set-RootPW -PlainText SuperSecret3 -Algorithm MD5
$VMHost | Set-ManagementNetwork -IPAddress 192.168.88.120 -NetworkMask 255.255.255.0 -Gateway 192.168.88.1 -VlanId 99 -Nameservers 192.168.88.10,192.168.10.11
$VMHost | Add-NTPSource -NTPSource 10.10.10.8
$VMHost | Add-NTPSource -NTPSource 10.10.11.8
$VMHost | Set-WelcomeMsg -WelcomeMsg $Msg
$VMHost | Set-Syslog -Address 10.10.11.20 -Port 514 -Protocol TCP
$VMHost | Set-SSLCertificate -CertPath .\Certificate\ESXi03Cert.crt -KeyPath .\Certificate\ESXi03Cert.Key
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch1
$vSwitch | Add-NetworkAdapter -vmnic vmnic4
$vSwitch | Add-NetworkAdapter -vmnic vmnic5
$vSwitch | Add-PortGroup -Name DC -VlanId 10
$vSwitch | Add-PortGroup -Name VCSA -VlanId 40
#Get-VMH "*" | Remove-VMH
Set-Paths -ISOPath "$PSScriptRoot\VMware-VMvisor-Installer-201912001-15160138.x86_64.iso" -WorkDirectory "$PSScriptRoot\source" -OutputDirectory "$PSScriptRoot\ISO"
Mount-ISO 
Set-SourceFiles
foreach ($VMH in (Get-VMH -Hostname "*").Hostname)
{
    New-KsScript -Hostname $VMH
    Write-ISO -ISOName $VMH

}
Dismount-DiskImage -DevicePath $ISO.DevicePath | Out-Null
Out-Json | Out-File "$PSScriptRoot\Current-Config.json" -Encoding ascii
Write-Host "Done :)"
