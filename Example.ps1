. .\ks_functions.ps1
$VMHost = Add-VMH -Hostname "ESXi01.test.local"
$VMHost | Set-RootPW -PlainText SuperSecret1 -Algorithm SHA512
$VMHost | Set-ManagementNetwork -IPAddress 192.168.88.120 -NetworkMask 255.255.255.0 -Gateway 192.168.88.1 -VlanId 99 -Nameservers 192.168.88.10,192.168.10.11
$VMHost | Add-NTPSource -NTPSource 10.10.10.8
$VMHost | Add-NTPSource -NTPSource 10.10.11.8
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
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch1
$vSwitch | Add-NetworkAdapter -vmnic vmnic4
$vSwitch | Add-NetworkAdapter -vmnic vmnic5
$vSwitch | Add-PortGroup -Name DC -VlanId 10
$vSwitch | Add-PortGroup -Name VCSA -VlanId 40
#Get-VMH "*" | Remove-VMH
Set-Paths -ISOPath "$PSScriptRoot\VMware-VMvisor-Installer-6.7.0.update03-14320388.x86_64.iso" -WorkDirectory "$PSScriptRoot\source" -OutputDirectory "$PSScriptRoot\ISO"
Mount-ISO 
Set-SourceFiles
foreach ($VMH in (Get-VMH -Hostname "*").Hostname)
{
    New-KsScript -Hostname $VMH
    Write-ISO -ISOName $VMH

}
Dismount-DiskImage -DevicePath $ISO.DevicePath | Out-Null
Write-Host "Done :)"
Out-Json | Out-File "Current-config.json" -Encoding ascii