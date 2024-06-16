$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if($isAdmin -eq $false){
    Write-Host "Run this script as administrator"
    exit 1
}

# Create Root CA
$rootCert = New-SelfSignedCertificate -DnsName "RootCA" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(10) -KeyUsage CertSign, DigitalSignature -KeySpec Signature -HashAlgorithm SHA256 -FriendlyName "Blog Root certificate"

# Export Root CA to .cer file
$rootCert | Export-Certificate -FilePath "RootCA.cer"

# Create Client Certificate
$clientCert = New-SelfSignedCertificate -DnsName "ClientCert" -CertStoreLocation "cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(1) -Signer $rootCert -KeyUsage DigitalSignature -HashAlgorithm SHA256 -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') -FriendlyName "Blog client certificate"

# Export Client Certificate to .pfx file (with private key)
$clientCert | Export-PfxCertificate -FilePath "ClientCert.pfx" -Password (ConvertTo-SecureString -String "your_password" -Force -AsPlainText)

# Export Client Certificate to .cer file (without private key)
$clientCert | Export-Certificate -FilePath "ClientCert.cer"

Write-Host "Generated RootCA.cer, ClientCert.pfx, and ClientCert.cer"

Import-Certificate -FilePath "RootCA.cer" -CertStoreLocation "cert:\LocalMachine\Root"

Write-Host "Imported RootCA.cer to root"