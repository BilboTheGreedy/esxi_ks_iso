Class vSphere {
    [vCenter]$vCenter
    [System.Collections.ArrayList]$Hosts = @()
    AddHost([string]$Name) {
        $newHost = [Host]::new($Name)
        $this.Hosts.Add($newHost)
    }
    AddvCenter([string]$SystemName,[string]$FQDN) {
        $new = [vCenter]::new($SystemName,$FQDN)
        $this.vCenter = $new
    }
}

class vCenter {
    [string]$FQDN
    [string]$SystemName
    [PSCredential]$SSOCredential
    [PSCredential]$OSCredential
    [SSL]$SSL
    vCenter([string]$SystemName,[string]$FQDN){
        $this.FQDN = $FQDN
        $this.SystemName = $SystemName
        $this.SSOCredential = Get-Credential -UserName "administrator@vsphere.local" -Message "SSO" 
        $this.OSCredential = Get-Credential -UserName "root" -Message "OS"

    }
    AddSSLCertificate([string]$Certificate,[string]$Key,[string]$CA) {
        $this.SSL = [SSL]::new($Certificate,$Key,$CA)
    }
}
class Host {
    [string]$Hostname
    [PSCredential]$OSCredential
    Host ([string]$Hostname){
        $this.Hostname = $Hostname
        $this.OSCredential = Get-Credential -UserName "root" -Message "OS"
    }
}

class SSL {
    [string]$Certificate
    [string]$Key
    [string]$CA
    SSL([string]$Certificate,[string]$Key,[string]$CA){
        $this.Certificate = $Certificate
        $this.Key = $Key
        $this.CA = $CA
    }
    
}

function Set-SSLCertificate {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [vSphere]$vSphere,
        [string]$CertPath,
        [string]$KeyPath,
        [string]$CAPath
    )
    if (test-path $CAPath ){
        $CARegex = [regex] "CERTIFICATE-----"
        if ( !(Get-Content $CAPath | Select-String -Pattern $CARegex)) {
            Write-Warning "CA certificate does not contain any certificate key start/end tags"
            exit
        }
    }
    else {
        Write-Warning "Unable to locate CA certificate"
        exit
    }
    if (test-path $CertPath ){
        $CertRegex = [regex] "CERTIFICATE-----"
        if ( !(Get-Content $CertPath | Select-String -Pattern $CertRegex)) {
            Write-Warning "certificate does not contain any certificate key start/end tags"
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
        $CA = (Get-Content $CAPath)
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
        foreach ($Line in $CA) {
            if ($line -notlike "-----END*")
            {
                $CAString += $line+"\n"
            }
            if ($line -like "-----END*")
            {
                $CAString += $line
            }
            
        }
        $vSphere.vCenter
        $vSphere.vCenter.AddSSLCertificate($CertString,$KeyString,$CAString)       
    
}

function Copy-SSLCerts {
    param (
        [Parameter(ValueFromPipeline)]
        [vSphere]$vSphere
    )
    $VM = Get-VM $vSphere.vCenter.SystemName
    Invoke-VMScript -ScriptText "echo -e `'$($vSphere.vCenter.SSL.Certificate)`' > /tmp/cert.crt;echo 'Certificate saved to /tmp/cert.crt'" -VM $VM -GuestCredential $vSphere.vCenter.OSCredential -ScriptType Bash
    Invoke-VMScript -ScriptText "echo -e `'$($vSphere.vCenter.SSL.Key)`' > /tmp/cert.key;echo 'Key saved to /tmp/cert.key'" -VM $VM -GuestCredential $vSphere.vCenter.OSCredential -ScriptType Bash
    Invoke-VMScript -ScriptText "echo -e `'$($vSphere.vCenter.SSL.CA)`' > /tmp/ca.key;echo 'Key saved to /tmp/ca.key'" -VM $VM -GuestCredential $vSphere.vCenter.OSCredential -ScriptType Bash
}

$vSphere = [vSphere]::new()
$vSphere.AddvCenter("VMware vCenter Server Appliance","192.168.88.201")
$vSphere.AddHost("192.168.88.198")
connect-ViServer $vSphere.Hosts[0].Hostname -Credential $vSphere.Hosts[0].OSCredential 
$vSphere | Set-SSLCertificate -CertPath .\Certificate\vcsa01.burger.local.crt -KeyPath .\Certificate\vcsa01.burger.local.pem -CAPath .\Certificate\CA_IS.crt
$vSphere | Copy-SSLCerts

