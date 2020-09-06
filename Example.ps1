. .\ks_functions.ps1
$RootPW = '$1$omividFt$audDHq6AfuZMXfQ6/TcWo1'
$VMHost = Add-VMH -Hostname "ESXi01.test.local"
$VMHost | Set-ManagementNetwork -IPAddress 192.168.88.120 -NetworkMask 255.255.255.0 -Gateway 192.168.88.1 -VlanId 99 -Nameservers 192.168.88.10,192.168.10.11
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch1 | Add-NetworkAdapter -vmnic vmnic4,vmnic5 
$vSwitch | Add-PortGroup -Name DC -VlanId 10
$vSwitch | Add-PortGroup -Name VCSA -VlanId 40
$VMHost = Add-VMH -Hostname "ESXi02.test.local"
$VMHost | Set-ManagementNetwork -IPAddress 192.168.88.120 -NetworkMask 255.255.255.0 -Gateway 192.168.88.1 -VlanId 99 -Nameservers 192.168.88.10,192.168.10.11
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch1 | Add-NetworkAdapter -vmnic vmnic4,vmnic5
$vSwitch | Add-PortGroup -Name DC -VlanId 10
$vSwitch | Add-PortGroup -Name VCSA -VlanId 40
$VMHost = Add-VMH -Hostname "ESXi03.test.local"
$VMHost | Set-ManagementNetwork -IPAddress 192.168.88.120 -NetworkMask 255.255.255.0 -Gateway 192.168.88.1 -VlanId 99 -Nameservers 192.168.88.10,192.168.10.11
$vSwitch = $VMHost | Add-vSwitch -Name vSwitch1 | Add-NetworkAdapter -vmnic vmnic4,vmnic5 
$vSwitch | Add-PortGroup -Name DC -VlanId 10
$vSwitch | Add-PortGroup -Name VCSA -VlanId 40
#Get-VMH "*" | Remove-VMH
Set-Paths -ISOPath "$PSScriptRoot\VMware-VMvisor-Installer-201912001-15160138.x86_64.iso" -WorkDirectory "$PSScriptRoot\source" -OutputDirectory "$PSScriptRoot\ISO"
Mount-ISO 
foreach ($VMH in (Get-VMH -Hostname "*").Hostname)
{

    Set-SourceFiles
    New-KsScript -Hostname $VMH
    Write-ISO -ISOName $VMH

}
Dismount-DiskImage -DevicePath $ISO.DevicePath | Out-Null
Write-Host "Done :)"
