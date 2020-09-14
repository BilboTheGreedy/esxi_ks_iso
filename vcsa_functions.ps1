Class vSphere {
    [vCenter]$vCenter
    [System.Collections.ArrayList]$Hosts = @()
    AddHost([string]$Name) {
        $newHost = [Host]::new($Name)
        $this.Hosts.Add($newHost)
    }
    AddVcenter([string]$Name) {
        $this.vCenter = [vCenter]::new($Name)
    }
}

class vCenter {
    [string]$Hostname
    [PSCredential]$SSOCredential
    [PSCredential]$OSCredential
    [SSL]$SSL
    vCenter($Hostname){
        $this.Hostname = $Hostname
        $this.SSOCredential = Get-Credential -UserName "administrator@vsphere.local" -Message "SSO" 
        $this.OSCredential = Get-Credential -UserName "root" -Message "OS"

    }
    AddSSLCertificate([string]$Certificate,[string]$Key) {
        $newCertificate = [SSL]::new($Certificate,$Key)
        $this.SSL = $newCertificate
    }
}
class Host {
    [string]$Hostname
    [PSCredential]$OSCredential
}

class SSL {
    [string]$Certificate
    [string]$Key
    SSL([string]$Certificate,[string]$Key){
        $this.Certificate = $Certificate
        $this.Key = $Key
    }
    
}

function Set-SSLCertificate {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [vSphere]$vSphere,
        [string]$CertPath,
        [string]$KeyPath
    )
    $vSphere
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
        $vSphere.vCenter.AddSSLCertificate($CertString,$KeyString)       
    
}

function Transfer-SSLCerts {
    param (
        [Parameter(ValueFromPipeline)]
        [vSphere]$vSphere
    )
    Invoke-VMScript -ScriptText "echo -e `'$($vSphere.vCenter.SSL.Certificate)`' > /tmp/rui.crt;echo 'Certificate saved to /tmp/rui.crt'" -VM $VM -GuestCredential $vSphere.vCenter.OSCredential -ScriptType Bash
    Invoke-VMScript -ScriptText "echo -e `'$($vSphere.vCenter.SSL.Key)`' > /tmp/rui.key;echo 'Key saved to /tmp/rui.key'" -VM $VM -GuestCredential $vSphere.vCenter.OSCredential -ScriptType Bash
}

$vSphere = [vSphere]::new()
$vSphere.AddVcenter("192.168.88.201")
$vSphere | Set-SSLCertificate -CertPath .\Certificate\vcsa01.burger.local.crt -KeyPath .\Certificate\vcsa01.burger.local.pem
$vSphere | Transfer-SSLCerts
