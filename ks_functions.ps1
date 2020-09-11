$ErrorActionPreference = "Stop"

class Host {
    [string]$Hostname
    [System.Collections.ArrayList]$NTPSources = @() 
    [Password]$Password
    [SSL]$SSL
    [Syslog]$Syslog
    [string]$WelcomeMsg
    [ManagementNetwork]$ManagementNetwork = [ManagementNetwork]::new()
    
    [System.Collections.ArrayList]$vSwitches = @()
    Host ([string]$Hostname) {
        $this.Hostname = $Hostname
    }
    AddvSwitch([string]$Name,[bool]$ModifyExisting) {
        $newSwitch = [vSwitch]::new($Name,$ModifyExisting)
        $this.vSwitches.Add($newSwitch)
    }
    AddNTPSource([string]$NTP) {
        $this.NTPSources.Add($NTP)
    }
    AddSSLCertificate([string]$Certificate,[string]$Key) {
        $newCertificate = [SSL]::new($Certificate,$Key)
        $this.SSL = $newCertificate
    }
    AddSyslogServer([string]$Address,[int]$Port,[string]$Protocol) {
        $newSyslog = [Syslog]::new($Address,$Port,$Protocol)
        $this.Syslog = $newSyslog
    }
    AddWelcomeMsg([string]$WelcomeMsg){
        $this.WelcomeMsg = $WelcomeMsg
    }

}

class Password {
    [string]$Hashed
    [string]$Algorithm
    [string]$PlainText
    [Void] GenerateCryptoHash () {
        $CryptoHash = Get-CryptHash $this.PlainText $this.Algorithm
        $this.Hashed = $CryptoHash 
    }
    
}

class SSL {
    [string]$Certificate
    [string]$Key
    SSL([string]$Certificate,[string]$Key){
        $this.Certificate = $Certificate
        $this.Key = $Key
    }
    
}
class Syslog {
    [string]$Address
    [int]$Port
    [string]$Protocol
    Syslog([string]$Address,[int]$Port,[string]$Protocol){
        $this.Address = $Address
        $this.Port = $Port
        $this.Protocol = $Protocol
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
    [bool]$ModifyExisting
    [System.Collections.ArrayList]$NetworkAdapters = @()
    [System.Collections.ArrayList]$PortGroups = @()
    vSwitch ([string]$Name,[bool]$ModifyExisting){
        $this.Name = $Name
        $this.ModifyExisting = $ModifyExisting
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
function Add-NTPSource {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$NTPSource
    )

    begin {

    }

    process {
        $Hostname.AddNTPSource($NTPSource)
    }

    end {

    }
}
function Set-SSLCertificate {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$CertPath,
        [string]$KeyPath
    )

    if (test-path $CertPath ){
        $CertRegex = [regex] "CERTIFICATE-----"
        if ( !(Get-Content $CertPath | Select-String -Pattern $CertRegex)) {
            Write-Warning "certificate does not contain any private key start/end tags"
            exit
        }
    }
    else {
        Write-Warning "Unable to locate certificate"
        exit
    }
    if (test-path $CertPath ){
        $KEYRegex = [regex] "PRIVATE\sKEY-----"
        if ( !(Get-Content $KeyPath | Select-String -Pattern $KEYRegex)) {
            Write-Warning "private key does not contain any private key start/end tags"
            exit
        }
    }
    else {
        Write-Warning "Unable to locate private key"
        exit
    }
    

        $Cert = (Get-Content $CertPath)
        $Key = (Get-Content $KeyPath)
        foreach ($Line in $Cert) {
            if ($line -notlike "-----END*")
            {
                $CertString += $line+"\n"
            }
            if ($line -like "-----END*")
            {
                $CertString += $line
            }
            
        }
        foreach ($Line in $Key) {
            if ($line -notlike "-----END*")
            {
                $KeyString += $line+"\n"
            }
            if ($line -like "-----END*")
            {
                $KeyString += $line
            }
            
            
        }

        $Hostname.AddSSLCertificate($CertString,$KeyString)
    
}

function Set-Syslog {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$Address,
        [string]$Port,
        [string]$Protocol
    )

    $Hostname.AddSyslogServer($Address,$Port,$Protocol)
    
}
function Set-WelcomeMsg {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$WelcomeMsg
    )

    $Hostname.AddWelcomeMsg($WelcomeMsg)
    
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
        [string]$Name,
        [bool]$ModifyExisting = $false
    )
    
    begin {
        if ($Hostname.vSwitches.Where({$_.Name -eq $Name})){
            Write-Error "A vSwitch with that name already exists"
            exit
        }
    }
    
    process {
        $Hostname.AddvSwitch($Name,$ModifyExisting)
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

function Format-RootPW {
    [CmdletBinding()]
    param (
        [string]$Name
    )
    

        $VMH = Get-VMH -Hostname $Name
        return $VMH.Password.Hashed

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

function Format-NTPSources {
    param (
        [string]$Name
    )
    $VMH = Get-VMH -Hostname $Name
    foreach ($NTPSource in $VMH.NTPSources)
    {
        $NTPSourcesResult += "echo `"`server $NTPSource`"` >> /etc/ntp.conf;`r`n"

    }
if ($NTPSourcesResult -ne $null) {
$result = @"
### Add NTP Server addresses
$($NTPSourcesResult.TrimEnd())
esxcli network firewall ruleset set --enabled=true --ruleset-id=ntpClient
/sbin/chkconfig ntpd on;
"@
return $result
}
else {
    return
}


}
function Format-vSwitch {
    [CmdletBinding()]
    param (
        [string]$Name
    )
    

        $VMH = Get-VMH -Hostname $Name
        $result ="#Standard vSwitches`r`n"
        foreach ($vSwitch in $VMH.vSwitches){
            if ($vSwitch.ModifyExisting){
                
            }
            else {
                $result += "esxcli network vswitch standard add --vswitch-name=$($vSwitch.Name)`r`n"
            }
            
        }
        return $result

}

function Format-PortGroup {
    [CmdletBinding()]
    param (
        [string]$Name
    )
    

        $VMH = Get-VMH -Hostname $Name
        $result ="#PortGroups`r`n"
        foreach ($vSwitch in $VMH.vSwitches)
        {
            foreach ($PortGroup in $vSwitch.PortGroups){
                
                $result += "esxcli network vswitch standard portgroup add --portgroup-name=$($PortGroup.Name) --vswitch-name=$($vSwitch.Name)`r`n"
                $result += "esxcli network vswitch standard portgroup set --portgroup-name=$($PortGroup.Name) --vlan-id=$($PortGroup.VlanId)`r`n"
            }
            
        }

        return $result
}

function Format-Syslog {
    param (
        [string]$Name
    )
    $VMH = Get-VMH -Hostname $Name
    $result ="#Syslog`r`n"
    $result +="esxcli system syslog config set --loghost='$($VMH.syslog.Protocol)://$($VMH.syslog.Address):$($VMH.syslog.Port)'`r`n"
    $result +="esxcli system syslog reload`r`n"
    return $result
}

function Format-SSLCertificate {
    param (
        [string]$Name
    )
    $VMH = Get-VMH -Hostname $Name
    $result ="#SSLCertificate`r`n"
    $result +="echo -e `'$($VMH.SSL.Certificate)`' > /etc/vmware/ssl/rui.crt`r`n"
    $result +="echo -e `'$($VMH.SSL.Key)`' > /etc/vmware/ssl/rui.key`r`n"
    $result +="services.sh restart`r`n"

    $result
}

function Format-Uplinks {
    param (
        [string]$Name
    )
    $VMH = Get-VMH -Hostname $Name
    $result ="#Uplinks`r`n"
    foreach ($vSwitch in $VMH.vSwitches)
    {
        foreach ($NetworkAdapter in $vSwitch.NetworkAdapters){
            
            $result += "esxcli network vswitch standard uplink add --uplink-name=$($NetworkAdapter.Name)  --vswitch-name=$($vSwitch.Name)`r`n"
        }
        
    }

    return $result
}

function Format-WelcomeMsg {
    param (
        [string]$Name
    )
    $VMH = Get-VMH -Hostname $Name
    $result = "#Welcome Message`r`n"
    $result += "esxcli system welcomemsg set  -m '$($VMH.WelcomeMsg)'`r`n"
    $result
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

rootpw --iscrypted $(Format-RootPW -Name $Hostname)
$(Format-ManagementNetwork -Name $Hostname)
install --firstdisk=local --overwritevmfs

keyboard 'Swedish'

reboot

%firstboot --interpreter=busybox

esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1
esxcli system settings advanced set -o /UserVars/HostClientCEIPOptIn -i 2
esxcli network ip set --ipv6-enabled=false

$(Format-vSwitch -Name $Hostname)
$(Format-Uplinks -Name $Hostname)
$(Format-PortGroup -Name $Hostname)
#Enable SSH and the ESXi Shell
vim-cmd hostsvc/enable_ssh
vim-cmd hostsvc/start_ssh
vim-cmd hostsvc/enable_esx_shell
vim-cmd hostsvc/start_esx_shell
$(Format-Syslog -Name $Hostname)
$(Format-NTPSources -Name $Hostname)
$(Format-SSLCertificate -Name $Hostname)
$(Format-WelcomeMsg -Name $Hostname)
#Enter Maintenance Mode
esxcli system maintenanceMode set -e true -t 60
#Reboot to persist changes
esxcli system shutdown reboot -d 15 -r "rebooting after ESXi host configuration"
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
    if (test-path $ISOPath ){
        $ISO.ISOPath = $ISOPath
    }
    else {
        Write-Warning "Unable to find $ISOPath"
        exit
    }
}        


function Write-ISO ($ISOName) {
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

$imgCreator.FileSystemsToCreate = 1
$imgCreator.FreeMediaBlocks = 0 # No size limit on ISO.

[byte[]] $bytes = 16,0,0,0,20,0,0,0 #or 16,0,0,0,0,0,0,0
$bootOptionsBios = New-Object -ComObject IMAPI2FS.BootOptions
$bootStreamBios = New-Object -ComObject ADODB.Stream
$bootStreamBios.Open()
$bootStreamBios.Type = 1 # Binary
$bootStreamBios.LoadFromFile((Get-Item ($ISO.Source+"\ISOLINUX.BIN")).FullName)
$bootStreamBios.Position = 8
$bootStreamBios.Write($bytes)
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
}

function Get-CryptHash {
    [CmdletBinding()]
    param (
        [string]$PlainText,
        [string]$Algorithm
    )
    
$Code = @'
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
namespace Crypt.Security.Cryptography {
    public static class Password {
        private static UTF8Encoding Utf8WithoutBom = new UTF8Encoding(false);
        private static RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        private static readonly char[] Base64Characters = new char[] { '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        private const Int32 MinimumSaltSize = 0;
        private const Int32 MaximumSaltSize = 16;
        private const Int32 MinimumIterationCount = 1000;
        private const Int32 MaximumIterationCount = 999999999;
        private const Int32 Md5DefaultIterationCount = 1000;
        private const Int32 Md5ApacheDefaultIterationCount = 1000;
        private const Int32 Sha256DefaultIterationCount = 5000;
        private const Int32 Sha512DefaultIterationCount = 5000;
        public static String Create(String password) {
            return Create(password, 16, PasswordAlgorithm.Sha512);
        }
        public static String Create(String password, PasswordAlgorithm algorithm) {
            if ((algorithm == PasswordAlgorithm.MD5) || (algorithm == PasswordAlgorithm.MD5Apache)) {
                return Create(password, 8, algorithm);
            } else {
                return Create(password, 16, algorithm);
            }
        }
        public static String Create(String password, Int32 saltSize, PasswordAlgorithm algorithm) {
            return Create(password, saltSize, algorithm, 0);
        }
        public static String Create(String password, Int32 saltSize, PasswordAlgorithm algorithm, Int32 iterationCount) {
            if (password == null) { throw new ArgumentNullException("password", "Password cannot be null."); }
            if (saltSize < Password.MinimumSaltSize) { saltSize = Password.MinimumSaltSize; }
            if (saltSize > Password.MaximumSaltSize) { saltSize = Password.MaximumSaltSize; }
            var salt = new byte[saltSize];
            Password.Rng.GetBytes(salt);
            for (int i = 0; i < salt.Length; i++) { //make it an ascii
                salt[i] = (byte)Password.Base64Characters[salt[i] % Password.Base64Characters.Length];
            }
            return Create(Password.Utf8WithoutBom.GetBytes(password), salt, algorithm, iterationCount);
        }
        public static String Create(Byte[] password, Byte[] salt, PasswordAlgorithm algorithm, Int32 iterationCount) {
            if (password == null) { throw new ArgumentNullException("password", "Password cannot be null."); }
            if (salt == null) { throw new ArgumentNullException("salt", "Salt cannot be null."); }
            if (iterationCount != 0) { //silently setup iterationCount to allowable limits (except for default value)
                if (iterationCount < Password.MinimumIterationCount) { iterationCount = Password.MinimumIterationCount; }
                if (iterationCount > Password.MaximumIterationCount) { iterationCount = Password.MaximumIterationCount; }
            }
            if (algorithm == PasswordAlgorithm.Default) { algorithm = PasswordAlgorithm.Sha512; }
            switch (algorithm) {
                case PasswordAlgorithm.MD5: return CreateMd5Basic(password, salt, iterationCount);
                case PasswordAlgorithm.MD5Apache: return CreateMd5Apache(password, salt, iterationCount);
                case PasswordAlgorithm.Sha256: return CreateSha256(password, salt, iterationCount);
                case PasswordAlgorithm.Sha512: return CreateSha512(password, salt, iterationCount);
                default: throw new ArgumentOutOfRangeException("algorithm", "Unknown algorithm.");
            }
        }
        public static Boolean Verify(String password, String passwordHash) {
            if (password == null) { throw new ArgumentNullException("password", "Password cannot be null."); }
            return Verify(Password.Utf8WithoutBom.GetBytes(password), passwordHash);
        }
        public static Boolean Verify(Byte[] password, String passwordHash) {
            if (password == null) { throw new ArgumentNullException("password", "Password cannot be null."); }
            if (passwordHash == null) { return false; }
            string id;
            int iterationCount;
            byte[] salt;
            string hash;
            if (!(SplitHashedPassword(passwordHash, out id, out iterationCount, out salt, out hash))) { return false; }
            string hashCalc;
            switch (id) { //algorithm
                case "1": SplitHashedPassword(CreateMd5Basic(password, salt, iterationCount), out hashCalc); break;
                case "apr1": SplitHashedPassword(CreateMd5Apache(password, salt, iterationCount), out hashCalc); break;
                case "5": SplitHashedPassword(CreateSha256(password, salt, iterationCount), out hashCalc); break;
                case "6": SplitHashedPassword(CreateSha512(password, salt, iterationCount), out hashCalc); break;
                default: return false;
            }
            return string.Equals(hash, hashCalc);
        }
        #region SHA 256/512
        private static string CreateSha256(byte[] password, byte[] salt, int iterationCount) {
            if (iterationCount == 0) { iterationCount = Password.Sha256DefaultIterationCount; }
            var c = CreateSha("SHA256", password, salt, iterationCount);
            var sb = new StringBuilder();
            sb.Append("$5$");
            if (iterationCount != Password.Sha256DefaultIterationCount) {
                sb.Append("rounds=" + iterationCount.ToString(CultureInfo.InvariantCulture) + "$");
            }
            sb.Append(ASCIIEncoding.ASCII.GetString(salt));
            sb.Append("$");
            Base64TripetFill(sb, c[00], c[10], c[20]);
            Base64TripetFill(sb, c[21], c[01], c[11]);
            Base64TripetFill(sb, c[12], c[22], c[02]);
            Base64TripetFill(sb, c[03], c[13], c[23]);
            Base64TripetFill(sb, c[24], c[04], c[14]);
            Base64TripetFill(sb, c[15], c[25], c[05]);
            Base64TripetFill(sb, c[06], c[16], c[26]);
            Base64TripetFill(sb, c[27], c[07], c[17]);
            Base64TripetFill(sb, c[18], c[28], c[08]);
            Base64TripetFill(sb, c[09], c[19], c[29]);
            Base64TripetFill(sb, null, c[31], c[30]);
            return sb.ToString();
        }
        private static string CreateSha512(byte[] password, byte[] salt, int iterationCount) {
            if (iterationCount == 0) { iterationCount = Password.Sha512DefaultIterationCount; }
            var c = CreateSha("SHA512", password, salt, iterationCount);
            var sb = new StringBuilder();
            sb.Append("$6$");
            if (iterationCount != Password.Sha512DefaultIterationCount) {
                sb.Append("rounds=" + iterationCount.ToString(CultureInfo.InvariantCulture) + "$");
            }
            sb.Append(ASCIIEncoding.ASCII.GetString(salt));
            sb.Append("$");
            Base64TripetFill(sb, c[00], c[21], c[42]);
            Base64TripetFill(sb, c[22], c[43], c[01]);
            Base64TripetFill(sb, c[44], c[02], c[23]);
            Base64TripetFill(sb, c[03], c[24], c[45]);
            Base64TripetFill(sb, c[25], c[46], c[04]);
            Base64TripetFill(sb, c[47], c[05], c[26]);
            Base64TripetFill(sb, c[06], c[27], c[48]);
            Base64TripetFill(sb, c[28], c[49], c[07]);
            Base64TripetFill(sb, c[50], c[08], c[29]);
            Base64TripetFill(sb, c[09], c[30], c[51]);
            Base64TripetFill(sb, c[31], c[52], c[10]);
            Base64TripetFill(sb, c[53], c[11], c[32]);
            Base64TripetFill(sb, c[12], c[33], c[54]);
            Base64TripetFill(sb, c[34], c[55], c[13]);
            Base64TripetFill(sb, c[56], c[14], c[35]);
            Base64TripetFill(sb, c[15], c[36], c[57]);
            Base64TripetFill(sb, c[37], c[58], c[16]);
            Base64TripetFill(sb, c[59], c[17], c[38]);
            Base64TripetFill(sb, c[18], c[39], c[60]);
            Base64TripetFill(sb, c[40], c[61], c[19]);
            Base64TripetFill(sb, c[62], c[20], c[41]);
            Base64TripetFill(sb, null, null, c[63]);
            return sb.ToString();
        }
        private static byte[] CreateSha(string hashName, byte[] password, byte[] salt, int iterationCount) {
            byte[] hashA;
            using (var digestA = HashAlgorithm.Create(hashName)) { //step 1
                AddDigest(digestA, password); //step 2
                AddDigest(digestA, salt); //step 3
                byte[] hashB;
                using (var digestB = HashAlgorithm.Create(hashName)) { //step 4
                    AddDigest(digestB, password); //step 5
                    AddDigest(digestB, salt);  //step 6
                    AddDigest(digestB, password); //step 7
                    hashB = FinishDigest(digestB); //step 8
                }
                AddRepeatedDigest(digestA, hashB, password.Length); //step 9/10
                var passwordLenght = password.Length;
                while (passwordLenght > 0) { //step 11
                    if ((passwordLenght & 0x01) != 0) { //bit 1
                        AddDigest(digestA, hashB);
                    } else { //bit 0
                        AddDigest(digestA, password);
                    }
                    passwordLenght >>= 1;
                }
                hashA = FinishDigest(digestA); //step 12
            }
            byte[] hashDP;
            using (var digestDP = HashAlgorithm.Create(hashName)) { //step 13
                for (int i = 0; i < password.Length; i++) { //step 14
                    AddDigest(digestDP, password);
                }
                hashDP = FinishDigest(digestDP); //step 15
            }
            var p = ProduceBytes(hashDP, password.Length); //step 16
            byte[] hashDS;
            using (var digestDS = HashAlgorithm.Create(hashName)) { //step 17
                for (int i = 0; i < (16 + hashA[0]); i++) { //step 18
                    AddDigest(digestDS, salt);
                }
                hashDS = FinishDigest(digestDS); //step 19
            }
            var s = ProduceBytes(hashDS, salt.Length); //step 20
            var hashAC = hashA;
            for (int i = 0; i < iterationCount; i++) { //step 21
                using (var digestC = HashAlgorithm.Create(hashName)) { //step 21a
                    if ((i % 2) == 1) { //step 21b
                        AddDigest(digestC, p);
                    } else { //step 21c
                        AddDigest(digestC, hashAC);
                    }
                    if ((i % 3) != 0) { AddDigest(digestC, s); } //step 21d
                    if ((i % 7) != 0) { AddDigest(digestC, p); } //step 21e
                    if ((i % 2) == 1) { //step 21f
                        AddDigest(digestC, hashAC);
                    } else { //step 21g
                        AddDigest(digestC, p);
                    }
                    hashAC = FinishDigest(digestC); //step 21h
                }
            }
            return hashAC;
        }
        #endregion
        #region MD5
        private static string CreateMd5Basic(byte[] password, byte[] salt, int iterationCount) {
            if (iterationCount == 0) { iterationCount = Password.Md5DefaultIterationCount; }
            return CreateMd5(password, salt, iterationCount, "$1$");
        }
        private static string CreateMd5Apache(byte[] password, byte[] salt, int iterationCount) {
            if (iterationCount == 0) { iterationCount = Password.Md5ApacheDefaultIterationCount; }
            return CreateMd5(password, salt, iterationCount, "$apr1$");
        }
        private static string CreateMd5(byte[] password, byte[] salt, int iterationCount, string magic) {
            byte[] hashA;
            using (var digestA = HashAlgorithm.Create("MD5")) { //step 1
                //password+magic+salt
                AddDigest(digestA, password); //step 2
                AddDigest(digestA, ASCIIEncoding.ASCII.GetBytes(magic));
                AddDigest(digestA, salt); //step 3
                byte[] hashB;
                using (var digestB = HashAlgorithm.Create("MD5")) { //step 4
                    AddDigest(digestB, password); //step 5
                    AddDigest(digestB, salt);  //step 6
                    AddDigest(digestB, password); //step 7
                    hashB = FinishDigest(digestB); //step 8
                }
                AddRepeatedDigest(digestA, hashB, password.Length); //step 9/10
                var passwordLenght = password.Length;
                while (passwordLenght > 0) { //step 11
                    if ((passwordLenght & 0x01) != 0) { //bit 1
                        AddDigest(digestA, new byte[] { 0x00 });
                    } else { //bit 0
                        AddDigest(digestA, new byte[] { password[0] });
                    }
                    passwordLenght >>= 1;
                }
                hashA = FinishDigest(digestA); //step 12
            }
            var hashAC = hashA;
            for (int i = 0; i < iterationCount; i++) { //step 21
                using (var digestC = HashAlgorithm.Create("MD5")) { //step 21a
                    if ((i % 2) == 1) { //step 21b
                        AddDigest(digestC, password);
                    } else { //step 21c
                        AddDigest(digestC, hashAC);
                    }
                    if ((i % 3) != 0) { AddDigest(digestC, salt); } //step 21d
                    if ((i % 7) != 0) { AddDigest(digestC, password); } //step 21e
                    if ((i % 2) == 1) { //step 21f
                        AddDigest(digestC, hashAC);
                    } else { //step 21g
                        AddDigest(digestC, password);
                    }
                    hashAC = FinishDigest(digestC); //step 21h
                }
            }
            var c = hashAC;
            var sb = new StringBuilder();
            sb.Append(magic);
            if (iterationCount != Password.Md5DefaultIterationCount) {
                sb.Append("rounds=" + iterationCount.ToString(CultureInfo.InvariantCulture) + "$");
            }
            sb.Append(ASCIIEncoding.ASCII.GetString(salt));
            sb.Append("$");
            Base64TripetFill(sb, c[00], c[06], c[12]);
            Base64TripetFill(sb, c[01], c[07], c[13]);
            Base64TripetFill(sb, c[02], c[08], c[14]);
            Base64TripetFill(sb, c[03], c[09], c[15]);
            Base64TripetFill(sb, c[04], c[10], c[05]);
            Base64TripetFill(sb, null, null, c[11]);
            return sb.ToString();
        }
        #endregion
        #region Helpers
        private static void AddDigest(HashAlgorithm digest, byte[] bytes) {
            if (bytes.Length == 0) { return; }
            var hashLen = digest.HashSize / 8;
            var offset = 0;
            var remaining = bytes.Length;
            while (remaining > 0) {
                digest.TransformBlock(bytes, offset, (remaining >= hashLen) ? hashLen : remaining, null, 0);
                remaining -= hashLen;
                offset += hashLen;
            }
        }
        private static void AddRepeatedDigest(HashAlgorithm digest, byte[] bytes, int length) {
            var hashLen = digest.HashSize / 8;
            while (length > 0) {
                digest.TransformBlock(bytes, 0, (length >= hashLen) ? hashLen : length, null, 0);
                length -= hashLen;
            }
        }
        private static byte[] ProduceBytes(byte[] hash, int lenght) {
            var hashLen = hash.Length;
            var produced = new byte[lenght];
            var offset = 0;
            while (lenght > 0) {
                Buffer.BlockCopy(hash, 0, produced, offset, (lenght >= hashLen) ? hashLen : lenght);
                offset += hashLen;
                lenght -= hashLen;
            }
            return produced;
        }
        private static byte[] FinishDigest(HashAlgorithm digest) {
            digest.TransformFinalBlock(new byte[] { }, 0, 0);
            return digest.Hash;
        }
        private static void Base64TripetFill(StringBuilder sb, byte? byte2, byte? byte1, byte? byte0) {
            if (byte0 != null) {
                sb.Append(Password.Base64Characters[byte0.Value & 0x3F]);
                if (byte1 != null) {
                    sb.Append(Password.Base64Characters[((byte1.Value & 0x0F) << 2) | (byte0.Value >> 6)]);
                    if (byte2 != null) {
                        sb.Append(Password.Base64Characters[((byte2.Value & 0x03) << 4) | (byte1.Value >> 4)]);
                        sb.Append(Password.Base64Characters[byte2.Value >> 2]);
                    } else {
                        sb.Append(Password.Base64Characters[byte1.Value >> 4]);
                    }
                } else {
                    sb.Append(Password.Base64Characters[byte0.Value >> 6]);
                }
            }
        }
        private static bool SplitHashedPassword(string hashedPassword, out string hash) {
            string id;
            int iterationCount;
            byte[] salt;
            return SplitHashedPassword(hashedPassword, out id, out iterationCount, out salt, out hash);
        }
        private static bool SplitHashedPassword(string hashedPassword, out string id, out int iterationCount, out byte[] salt, out string hash) {
            id = null;
            iterationCount = 0;
            salt = null;
            hash = null;
            var parts = hashedPassword.Split('$');
            if (parts.Length < 4) { return false; }
            id = parts[1];
            if (parts[2].StartsWith("rounds=", StringComparison.Ordinal) && (parts.Length >= 5) && (int.TryParse(parts[2].Substring(7), NumberStyles.Integer, CultureInfo.InvariantCulture, out iterationCount))) {
                salt = ASCIIEncoding.ASCII.GetBytes(parts[3]);
                hash = parts[4];
            } else {
                iterationCount = 0;
                salt = ASCIIEncoding.ASCII.GetBytes(parts[2]);
                hash = parts[3];
            }
            return true;
        }
        #endregion
    }
    
    
    
    public enum PasswordAlgorithm {
        Default = 0,
        MD5 = 10,
        MD5Apache = 11,
        Sha256 = 50,
        Sha512 = 60,
    }
}

'@

Add-Type  -TypeDefinition $code -Language CSharp
    
    

        $Result = [Crypt.Security.Cryptography.Password]::Create($PlainText,$Algorithm)
 
        return $Result
    
}
function Set-RootPW {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [Host]$Hostname,
        [string]$PlainText,
        [string]$Algorithm
    )
    
    begin {
    }
    
    process {
        $Hostname.Password = [Password]::New()
        $Hostname.Password.PlainText = $PlainText
        $Hostname.Password.Algorithm = $Algorithm
        $Hostname.Password.GenerateCryptoHash()
    }
    
    end {
    }
}
function Set-SourceFiles {
    param (
    )
    if (!(Test-Path $ISO.Source -PathType Container)){mkdir $ISO.Source|Out-Null}
    Copy-Item ($ISO.Drive+"\*") -Destination $ISO.Source -Force -Recurse
    Set-ItemProperty ($ISO.Source+"\BOOT.CFG") -Name isReadOnly -Value $False
    (Get-Content ($ISO.Source+"\BOOT.CFG")).Replace("cdromBoot","ks=cdrom:/KS.CFG") | Set-Content ($ISO.Source+"\BOOT.CFG")
    Set-ItemProperty ($ISO.Source+"\EFI\BOOT\BOOT.CFG") -Name isReadOnly -Value $False
    (Get-Content ($ISO.Source+"\EFI\BOOT\BOOT.CFG")).Replace("cdromBoot","ks=cdrom:/KS.CFG") | Set-Content ($ISO.Source+"\EFI\BOOT\BOOT.CFG")

    
}

function Out-Json {
    $vSphere | ConvertTo-Json -Depth 100
    
}

if ($vSphere) {Remove-Variable vSphere}
