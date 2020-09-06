class Host {
    [string]$Hostname
    [string[]]$NTPSources
    [ManagementNetwork]$ManagementNetwork = [ManagementNetwork]::new()
    
    [System.Collections.ArrayList]$vSwitches = @()
    Host ([string]$Hostname) {
        $this.Hostname = $Hostname
    }
    AddvSwitch([string]$Name) {
        $newSwitch = [vSwitch]::new($Name)
        $this.vSwitches.Add($newSwitch)
    }

}

Class vSphere {
    [System.Collections.ArrayList]$Hosts = @()
    AddHost([string]$Name) {
        $newHost = [Host]::new($Name)
        $this.Hosts.Add($newHost)
    }
}

Class vSwitch {
    [string]$Name
    [System.Collections.ArrayList]$NetworkAdapters = @()
    [System.Collections.ArrayList]$PortGroups = @()
    vSwitch ([string]$Name){
        $this.Name = $Name
    }

    AddNetworkAdapter([string]$Name) {
        $newAddNetworkAdapter = [NetworkAdapter]::new($Name)
        $this.NetworkAdapters.Add($newAddNetworkAdapter)
    }
    AddPortGroup([string]$Name,[int]$VlanId) {
        $newPortGroup = [PortGroup]::new($Name,$VlanId)
        $this.PortGroups.Add($newPortGroup)
    }
    
}

Class PortGroup {
    [string]$Name
    [int]$VlanId
    PortGroup ([string]$Name,[int]$VlanId){
        $this.Name = $Name
        $this.VlanId = $VlanId
    }
}

Class NetworkAdapter {
    [string]$Name

    NetworkAdapter ([string]$Name){
        $this.Name = $Name
    }
}

Class ManagementNetwork {
    [string]$IPAddress
    [string]$NetworkMask
    [string]$Gateway
    [int]$VlanId
    [string[]]$Nameservers

}

class ISO {
    [string]$Source
    [string]$Output
    [string]$ISOPath
    [string]$Drive
    [string]$DevicePath
}

function Add-VMH {
    [CmdletBinding()]
    param (
        [string]$Hostname
    )
    
    begin {
        if (!$vSphere){
            New-Variable -Name vSphere -Value ([vSphere]::New()) -Scope global
        }
        if ($vSphere.Hosts.Where({$_.Hostname -eq $Hostname})){
            Write-Error "A host with that name already exists"
        }
    }
    
    process {
        if (!$vSphere.Hosts.Where({$_.Hostname -eq $Hostname})){
            $vSphere.AddHost($Hostname)
        }
       
    }
    
    end {
        return $vSphere.Hosts.Where({$_.Hostname -eq $Hostname})
    }
}

function Remove-VMH {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname
    )
    
    begin {
    }
    
    process {
        $vSphere.Hosts.Remove($Hostname)
    }
    
    end {
    }
}

function Get-VMH {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Hostname
    )
    
    begin {
    }
    
    process {
        if ($vSphere){
            if ($Hostname){
                $vSphere.Hosts.Where({$_.Hostname -like $Hostname})
            }
            else {
            }
            
        }
    }
    
    end {

    }
}

function Set-ManagementNetwork {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$IPAddress,
        [string]$NetworkMask,
        [string]$Gateway,
        [int]$VlanId,
        [string[]]$Nameservers
    )
    
    begin {
        if ($Nameservers.Length -gt 2){
            Write-Error "You can only specify two Nameservers"
            exit
        }
    }
    
    process {
        $Hostname.ManagementNetwork.IPAddress = $IPAddress
        $Hostname.ManagementNetwork.NetworkMask = $NetworkMask
        $Hostname.ManagementNetwork.Gateway = $Gateway
        $Hostname.ManagementNetwork.VlanId = $VlanId
        $Hostname.ManagementNetwork.Nameservers = $Nameservers

    }
    
    end {

    }
}

function Add-vSwitch {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$Name
    )
    
    begin {
        if ($Hostname.vSwitches.Where({$_.Name -eq $Name})){
            Write-Error "A vSwitch with that name already exists"
            exit
        }
    }
    
    process {
        $Hostname.AddvSwitch($Name)
    }
    
    end {
        $Hostname.vSwitches.Where({$_.Name -eq $Name})
    }
}

function Get-vSwitch {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$Name
    )
    
    begin {
    }
    
    process {
        $vSwitch = $Hostname.vSwitches.Where({$_.Name -eq $Name})
    }
    
    end {
        $vSwitch
    }
}

function Add-NetworkAdapter {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [vSwitch]$vSwitch,
        [string[]]$vmnic
    )
    
    begin {

    }
    
    process {
        $vSwitch.AddNetworkAdapter($vmnic)
    }
    
    end {
        $vSwitch
    }
}

function Add-PortGroup {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [vSwitch]$vSwitch,
        [string]$Name,
        [int]$VlanId
    )
    
    begin {

    }
    
    process {
        if ($vSwitch.PortGroups.Where({$_.Name -eq $Name})){
            Write-Error "A PortGroup with that name already exists"
            exit
        }
        else {
          $vSwitch.AddPortGroup($Name,$VlanId)  
        }
        
    }
    
    end {
    }
}
function Format-ManagementNetwork {
    [CmdletBinding()]
    param (
        [string]$Name
    )
    

        $VMH = Get-VMH -Hostname $Name
        if ($VMH.ManagementNetwork.VlanId -eq 0) {
            $result = "network --bootproto=static --ip=$($VMH.ManagementNetwork.IPAddress) --netmask=$($VMH.ManagementNetwork.NetworkMask) --gateway=$($VMH.ManagementNetwork.Gateway) --nameserver=$($VMH.ManagementNetwork.Nameservers -join ',') --hostname=$($VMH.Hostname)`r"    
        }
        else {
            $result = "network --bootproto=static --vlanid=$($VMH.ManagementNetwork.VlanId)  --ip=$($VMH.ManagementNetwork.IPAddress) --netmask=$($VMH.ManagementNetwork.NetworkMask) --gateway=$($VMH.ManagementNetwork.Gateway) --nameserver=$($VMH.ManagementNetwork.Nameservers -join ',') --hostname=$($VMH.Hostname)`r"    
        }
        return $result

}
function Format-vSwitch {
    [CmdletBinding()]
    param (
        [string]$Name
    )
    

        $VMH = Get-VMH -Hostname $Name
        foreach ($vSwitch in $VMH.vSwitches){
            $result ="#Standard vSwitches`r`n"
            $result += "esxcli network vswitch standard add --vswitch-name=$($vSwitch.Name)`r`n"
        }
        return $result

}

function Format-PortGroup {
    [CmdletBinding()]
    param (
        [string]$Name
    )
    

        $VMH = Get-VMH -Hostname $Name
        foreach ($vSwitch in $VMH.vSwitches)
        {
            foreach ($PortGroup in $vSwitch.PortGroups){
                $result ="#PortGroups`r`n"
                $result += "esxcli network vswitch standard portgroup add --portgroup-name=$($PortGroup.Name) --vswitch-name=$($vSwitch.Name)`r`n"
                $result += "esxcli network vswitch standard portgroup set --portgroup-name=$($PortGroup.Name) --vlan-id=$($PortGroup.VlanId)`r`n"
            }
            
        }

        return $result
}

function Format-Uplinks {
    param (
        [string]$Name
    )
    $VMH = Get-VMH -Hostname $Name
    foreach ($vSwitch in $VMH.vSwitches)
    {
        foreach ($NetworkAdapter in $vSwitch.NetworkAdapters){
            $result ="#Uplinks`r`n"
            $result += "esxcli network vswitch standard uplink add --uplink-name=$($NetworkAdapter)  --vswitch-name=$($vSwitch.Name)`r`n"
        }
        
    }

    return $result
}

function New-RootPW {
    Param (
        [Parameter(Mandatory=$true)]
        [string]
        $ClearString
    )
    
    $ClearString
}
function New-KsScript {
    [CmdletBinding()]
    param (
        [string]$Hostname
    )
    
    begin {
        Write-Host "Generating Kickstart script for $Hostname"
    }
    
    process {
$ks_tmpl = @"
accepteula

rootpw --iscrypted $(New-RootPW -ClearString $RootPW)
$(Format-ManagementNetwork -Name $Hostname)
install --firstdisk=local --overwritevmfs

keyboard 'Swedish'

reboot

%firstboot --interpreter=busybox

$(Format-vSwitch -Name $Hostname)
$(Format-Uplinks -Name $Hostname)
$(Format-PortGroup -Name $Hostname)
#Enable SSH and the ESXi Shell
vim-cmd hostsvc/enable_ssh
vim-cmd hostsvc/start_ssh
vim-cmd hostsvc/enable_esx_shell
vim-cmd hostsvc/start_esx_shell
esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1
"@
    }
    
    end {
        $ks_tmpl | Out-File ($ISO.Source+"\KS.CFG") -Encoding ascii -Force
    }
}

function Mount-ISO {

    begin {
        Write-Host "Mounting ISO: $($ISO.ISOPath)"
        if (!$ISO){
            New-Variable -Name ISO -Value ([ISO]::New()) -Scope global
        }
    }
    
    process {
        $Mount = Mount-DiskImage -PassThru $ISO.ISOPath
        $ISO.Drive = ($mount | get-volume).driveletter + ':\'
        $ISO.DevicePath = $Mount.DevicePath
    }
    
    end {
    }
}


function Set-Paths {
    param (
        [string]$ISOPath,
        [string]$WorkDirectory,
        [string]$OutputDirectory

    )
    if (!$ISO){
        New-Variable -Name ISO -Value ([ISO]::New()) -Scope global
    }
    $ISO.Source = $WorkDirectory
    $ISO.Output = $OutputDirectory
    $ISO.ISOPath = $ISOPath
}        


function Write-ISO ($ISOName) {
#Start-Task "Writing install media iso" -Tags WriteMediaISO
Write-Host "Writing ISO file $($ISO.Output+"\"+$ISOName)"
$cmpParams = New-Object System.CodeDom.Compiler.CompilerParameters -Property @{
    CompilerOptions = "/unsafe"
    WarningLevel = 4
    TreatWarningsAsErrors = $true
}

Add-Type -CompilerParameters $cmpParams -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;

namespace Builder {
    public static class ISOWriter {
    public static void WriteIStreamToFile (object comObject, string fileName) {
        IStream inputStream = comObject as IStream;
        FileStream outputStream = File.OpenWrite(fileName);

        byte[] data;
        int bytesRead;

        do {
        data = Read(inputStream, 2048, out bytesRead);
        outputStream.Write(data, 0, bytesRead);
        } while (bytesRead == 2048);

        outputStream.Flush();
        outputStream.Close();
    }

    unsafe static private byte[] Read(IStream stream, int toRead, out int read) {
        byte[] buffer = new byte[toRead];

        int bytesRead = 0;

        int* ptr = &bytesRead;

        stream.Read(buffer, toRead, (IntPtr)ptr);

        read = bytesRead;

        return buffer;
    }
    }
}
"@


$platformId = @{
    x86 = 0
    EFI = 0xEF
}

$emulationType = @{
    None = 0
}

$imgCreator = New-Object -ComObject IMAPI2FS.MsftFileSystemImage

$imgCreator.FileSystemsToCreate = 3
$imgCreator.FreeMediaBlocks = 0 # No size limit on ISO.

$bootOptionsBios = New-Object -ComObject IMAPI2FS.BootOptions
$bootStreamBios = New-Object -ComObject ADODB.Stream
$bootStreamBios.Open()
$bootStreamBios.Type = 1 # Binary
$bootStreamBios.LoadFromFile((Get-Item ($ISO.Source+"\ISOLINUX.BIN")).FullName)
$bootOptionsBios.AssignBootImage($bootStreamBios)
$bootOptionsBios.PlatformId = $platformId.x86
$bootOptionsBios.Emulation = $emulationType.None

$bootOptionsEfi = New-Object -ComObject IMAPI2FS.BootOptions
$bootStreamEfi = New-Object -ComObject ADODB.Stream
$bootStreamEfi.Open()
$bootStreamEfi.Type = 1 # Binary
$bootStreamEfi.LoadFromFile((Get-Item ($ISO.Source+"\EFIBOOT.IMG")).FullName)
$bootOptionsEfi.AssignBootImage($bootStreamEfi)
$bootOptionsEfi.PlatformId = $platformId.EFI
$bootOptionsEfi.Emulation = $emulationType.None

$bootOptions = [System.Array]::CreateInstance([Object], 2)
$bootOptions.SetValue($bootOptionsBios, 0)
$bootOptions.SetValue($bootOptionsEfi, 1)

$imgCreator.BootImageOptionsArray = $bootOptions

$imgCreatorRoot = $imgCreator.Root

$imgCreatorRoot.AddTree($ISO.Source, $false)

$resultImage = $imgCreator.CreateResultImage()
if (!(test-path $iso.Output -PathType Container)) {mkdir $iso.Output | Out-Null}
[Builder.ISOWriter]::WriteIStreamToFile(
    $resultImage.ImageStream,
    ($ISO.Output + "\" + $ISOName + ".ISO").ToUpper()
)

while ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($resultImage) -gt 0) {}
while ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($imgCreatorRoot) -gt 0) {}
while ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($bootOptionsBios) -gt 0) {}
while ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($bootStreamBios) -gt 0) {}
while ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($bootOptionsEfi) -gt 0) {}
while ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($bootStreamEfi) -gt 0) {}
while ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($imgCreator) -gt 0) {}

[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

#Complete-Task -Status Info "Done!"
}

function Set-SourceFiles {
    param (
    )
    Copy-Item ($ISO.Drive+"\*") -Destination $ISO.Source -Force -Recurse
    Set-ItemProperty ($ISO.Source+"\BOOT.CFG") -Name isReadOnly -Value $False
    (Get-Content ($ISO.Source+"\BOOT.CFG")).Replace("cdromBoot","ks=cdrom:/KS.CFG") | Set-Content ($ISO.Source+"\BOOT.CFG")
    Set-ItemProperty ($ISO.Source+"\EFI\BOOT\BOOT.CFG") -Name isReadOnly -Value $False
    (Get-Content ($ISO.Source+"\EFI\BOOT\BOOT.CFG")).Replace("cdromBoot","ks=cdrom:/KS.CFG") | Set-Content ($ISO.Source+"\EFI\BOOT\BOOT.CFG")

    
}

if ($vSphere) {Remove-Variable vSphere}


