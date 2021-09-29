# Join domain before proceeding

Import-Module ServerManager
Add-WindowsFeature -Name "RSAT-AD-PowerShell" –IncludeAllSubFeature
Add-WindowsFeature -IncludeManagementTools -Name ADFS-Federation
Import-Module ActiveDirectory
Import-Module ADFS

$domain = Get-ADDomain
$dns_root = $domain.DNSRoot
$fqdn = $env:COMPUTERNAME + "." + $dns_root
$aws_account_number = "1111111111"
$group_name = "AWS-" + $aws_account_number + "-Admins"

$domain_admin_credential = Get-Credential

$path_to_adfs_cert = "adfs.pfx"
$certificate = Import-PfxCertificate -FilePath $path_to_adfs_cert -CertStoreLocation Cert:\LocalMachine\My

Install-AdfsFarm -CertificateThumbprint $certificate.Thumbprint -FederationServiceName $fqdn -ServiceAccountCredential $domain_admin_credential

New-ADOrganizationalUnit -Name "ADFS2" -Path "DC=teokyllc,DC=internal" -ProtectedFromAccidentalDeletion $False
New-ADGroup -Name "ADFS-Access2" -SamAccountName ADFS-Access2 -GroupCategory Security -GroupScope Global -DisplayName "ADFS-Access2" -Path "OU=ADFS2,DC=teokyllc,DC=internal" -Description "Access to use ADFS."
New-ADGroup -Name $group_name -SamAccountName $group_name -GroupCategory Security -GroupScope Global -DisplayName $group_name -Path "OU=ADFS2,DC=teokyllc,DC=internal" -Description "Users allowed to login to AWS account."
Add-ADGroupMember -Identity "ADFS-Access2" -Members "CN=Allan Taylor,CN=Users,DC=teokyllc,DC=internal"
Add-ADGroupMember -Identity $group_name -Members "CN=Allan Taylor,CN=Users,DC=teokyllc,DC=internal"

$relay_trust_name = "AWS-" + $aws_account_number
Add-ADFSRelyingPartyTrust -Name $relay_trust_name -MetadataURL "https://signin.aws.amazon.com/static/saml-metadata.xml" -MonitoringEnabled $true -AutoUpdateEnabled $true
Set-AdfsProperties -EnableIdPInitiatedSignonPage $true

# Add claim access policy "Permit specific group"

# Edit claims issuance policy

# 1. Claim rule template - Transform an Incoming claim
# Name: NameId
# Income claim type: Windows account name
# Outgoing claim type: Name ID
# Outgoing name ID format: Persistent indentifier

# Be sure the email address is set on AD users

# 2. Claim rule template - Send LDAP Attributes as Claims
# Name: RoleSessionName
# Attribute store: Active Directory
# LDAP attribute: E-Mail-Addresses
# Outgoing Claim Type: https://aws.amazon.com/SAML/Attributes/RoleSessionName

# 3. Claim rule template - Send claims using a custom rule
# Name: Get AD Groups
# Custom rule:
# c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("http://TEOKYLLC/groups"), query = ";tokenGroups;{0}", param = c.Value);

# 4. Claim rule template - Send claims using a custom rule
# Name: Roles
# Custom rule:
# c:[Type == "http://TEOKYLLC/groups", Value =~ "(?i)^AWS-1111111111-Admins"] => issue(Type = "https://aws.amazon.com/SAML/Attributes/Role", Value = RegExReplace(c.Value, "AWS-1111111111-Admins", "arn:aws:iam::1111111111:saml-provider/ADFS,arn:aws:iam::1111111111:role/TEOKYLLC-Admins"));
#                                                     ^ AD group name                                                                                                         ^ AD group name            ^ SAML provider ARN                          ^ User role being assumed ARN
