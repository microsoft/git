param(
    [Parameter(Mandatory=$true)]
    [string]$VaultName,

    [Parameter(Mandatory=$true)]
    [string]$TempDir,

    [Parameter(Mandatory=$true)]
    [string[]]$CertNames
)

# Download certificates from Azure Key Vault and import them into the
# local machine certificate store. Requires an authenticated Azure CLI
# session (e.g., via AzureCLI@2 task).

foreach ($name in $CertNames) {
    $pfxPath = Join-Path $TempDir "$name.pfx"
    try {
        Write-Host "Downloading certificate: $name"
        az keyvault secret download `
            --vault-name $VaultName `
            --name $name `
            --file $pfxPath `
            --encoding base64
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to download certificate '$name'"
        }

        Write-Host "Importing certificate: $name"
        $cert = Import-PfxCertificate `
            -FilePath $pfxPath `
            -CertStoreLocation "Cert:\LocalMachine\My"
        Write-Host "  Thumbprint: $($cert.Thumbprint)"
    } finally {
        if (Test-Path $pfxPath) {
            Remove-Item $pfxPath -Force
        }
    }
}
