param(
    [Parameter(Mandatory=$true)]
    [string]$SearchPath
)

# Locate ESRPClient.exe under the given path and set a pipeline variable.

$esrpTool = Get-ChildItem -Path $SearchPath -Filter "ESRPClient.exe" -Recurse |
    Select-Object -First 1

if (-not $esrpTool) {
    Write-Error "ESRPClient.exe not found under $SearchPath"
    exit 1
}

Write-Host "Found ESRP client: $($esrpTool.FullName)"
Write-Host "##vso[task.setvariable variable=ESRP_TOOL]$($esrpTool.FullName)"
