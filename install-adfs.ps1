# Join domain before proceeding

Import-Module ServerManager
Add-WindowsFeature -Name "RSAT-AD-PowerShell" –IncludeAllSubFeature
Add-WindowsFeature -IncludeManagementTools -Name ADFS-Federation
Import-Module ActiveDirectory
Import-Module ADFS

$domain = Get-ADDomain
$dns_root = $domain.DNSRoot
$fqdn = "adfs." + $dns_root

$domain_admin_credential = Get-Credential

$path_to_adfs_cert = "adfs.pfx"
$certificate = Import-PfxCertificate -FilePath $path_to_adfs_cert -CertStoreLocation Cert:\LocalMachine\My

Install-AdfsFarm -CertificateThumbprint $certificate.Thumbprint -FederationServiceName $fqdn -ServiceAccountCredential $domain_admin_credential
