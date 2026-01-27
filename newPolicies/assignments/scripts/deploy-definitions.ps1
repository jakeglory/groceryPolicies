param(
  [Parameter(Mandatory=$true)] [string] $TenantRootManagementGroupId,
  [string] $Location = 'westeurope',
  [int] $ThrottleLimit = 10,
  [ValidateSet('Policies','PolicySets','Both')]
  [string] $Mode = 'Both'
)

$ErrorActionPreference = 'Stop'

Write-Host "Deploying policy definitions and policy set definitions to MG: $TenantRootManagementGroupId"

# Discover JSON files (rely on folder location; no filename suffix required)
$policyDefs = Get-ChildItem -Path "$PSScriptRoot/../definitions/policyDefinitions" -Filter *.json -Recurse -ErrorAction SilentlyContinue
$policySets = Get-ChildItem -Path "$PSScriptRoot/../definitions/policySetDefinitions" -Filter *.json -Recurse -ErrorAction SilentlyContinue

# Pre-run counts
$policyTotal   = ($policyDefs | Measure-Object | Select-Object -ExpandProperty Count)
$policySetTotal= ($policySets | Measure-Object | Select-Object -ExpandProperty Count)
if ($Mode -in @('Policies','Both'))    { Write-Host ("Found {0} policy definition file(s) to process" -f $policyTotal) }
if ($Mode -in @('PolicySets','Both'))  { Write-Host ("Found {0} policy set (initiative) file(s) to process" -f $policySetTotal) }

# Result tracking
$policyResults    = @()
$policySetResults = @()

# Prepare deployment lists
$policyDefsToDeploy = @()
if ($Mode -in @('Policies','Both')) {
  foreach ($file in $policyDefs) {
    $filePath = $file.FullName
    $fileName = $file.Name
    try {
      $local = Get-Content -Raw -Path $filePath | ConvertFrom-Json -AsHashtable
      $name  = if ($local.name) { $local.name } else { $fileName }
    } catch {
      Write-Host "[Policy][ParseError] $fileName -> $($_.Exception.Message)"
      $policyResults += [pscustomobject]@{ Type='Policy'; Name=$fileName; File=$filePath; Succeeded=$false; Reason='InvalidJson' }
      continue
    }
    $policyDefsToDeploy += ,([pscustomobject]@{ File=$filePath; Name=$name })
  }
  Write-Host ("Policies to deploy: {0}" -f ($policyDefsToDeploy.Count))
}

$policySetsToDeploy = @()
if ($Mode -in @('PolicySets','Both')) {
  foreach ($file in $policySets) {
    $filePath = $file.FullName
    $fileName = $file.Name
    try {
      $localText = Get-Content -Raw -Path $filePath
      $localText = $localText -replace '\$\{tenantRootMgId\}', $TenantRootManagementGroupId
      $local = $localText | ConvertFrom-Json -AsHashtable
      $name  = if ($local.name) { $local.name } else { $fileName }
    } catch {
      Write-Host "[PolicySet][ParseError] $fileName -> $($_.Exception.Message)"
      $policySetResults += [pscustomobject]@{ Type='PolicySet'; Name=$fileName; File=$filePath; Succeeded=$false; Reason='InvalidJson' }
      continue
    }
    $policySetsToDeploy += ,([pscustomobject]@{ File=$filePath; Name=$name })
  }
  Write-Host ("Policy sets to deploy: {0}" -f ($policySetsToDeploy.Count))
}

$supportsParallel = ($PSVersionTable.PSVersion.Major -ge 7)
if ($supportsParallel) {
  Write-Host "PowerShell $($PSVersionTable.PSVersion.ToString()) supports parallelism. Using ThrottleLimit=$ThrottleLimit."
} else {
  Write-Host "PowerShell $($PSVersionTable.PSVersion.ToString()) does not support ForEach-Object -Parallel. Running sequentially."
}

if ($Mode -in @('Policies','Both')) {
  # Deploy policies
  if ($supportsParallel) {
    $policyResults = $policyDefsToDeploy | ForEach-Object -Parallel {
      $filePath = $_.File
      $fileName = [System.IO.Path]::GetFileName($filePath)
      $success = $false
      $name = $_.Name
      $json = Get-Content -Raw -Path $filePath | ConvertFrom-Json -AsHashtable
      Write-Host "[Policy][Start] $name ($fileName)"
      # Build ARM parameter file shape
      $paramsArm = @{
        parameters = @{
          policyJson = @{ value = $json }
          baseName   = @{ value = $name }
        }
      }
      $tmp = New-TemporaryFile
      $paramsArm | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding UTF8
      $maxAttempts = 3
      for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        az deployment mg create `
          --management-group-id $using:TenantRootManagementGroupId `
          --name "policy-$($name)" `
          --location $using:Location `
          --template-file "$using:PSScriptRoot/../infra/bicep/modules/policyDefinitionFromFile.bicep" `
          --parameters @$tmp `
          --only-show-errors `
          --output none
        if ($LASTEXITCODE -eq 0) { $success = $true; break }
        if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds (2 * $attempt) }
      }
      if ($success) { Write-Host "[Policy][Success] $name" } else { Write-Host "[Policy][Failed] $name" }
      [pscustomobject]@{ Type='Policy'; Name=$name; File=$filePath; Succeeded=$success }
    } -ThrottleLimit $ThrottleLimit
  } else {
    foreach ($item in $policyDefsToDeploy) {
      $filePath = $item.File
      $fileName = [System.IO.Path]::GetFileName($filePath)
      $name = $item.Name
      $json = Get-Content -Raw -Path $filePath | ConvertFrom-Json -AsHashtable
  Write-Host "[Policy][Start] $name ($fileName)"
      # Build ARM parameter file shape
      $paramsArm = @{
        parameters = @{
          policyJson = @{ value = $json }
          baseName   = @{ value = $name }
        }
      }
      $tmp = New-TemporaryFile
      $paramsArm | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding UTF8
      $success = $false
      $maxAttempts = 3
      for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        az deployment mg create `
          --management-group-id $TenantRootManagementGroupId `
          --name "policy-$($name)" `
          --location $Location `
          --template-file "$PSScriptRoot/../infra/bicep/modules/policyDefinitionFromFile.bicep" `
          --parameters @$tmp `
          --only-show-errors `
          --output none
        if ($LASTEXITCODE -eq 0) { $success = $true; break }
        if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds (2 * $attempt) }
      }
      if ($success) { Write-Host "[Policy][Success] $name" } else { Write-Host "[Policy][Failed] $name" }
      $policyResults += [pscustomobject]@{ Type='Policy'; Name=$name; File=$filePath; Succeeded=$success }
    }
  }
}

# Deploy policy sets
if ($Mode -in @('PolicySets','Both')) {
  if ($supportsParallel) {
    $policySetResults = $policySetsToDeploy | ForEach-Object -Parallel {
      $filePath = $_.File
      $fileName = [System.IO.Path]::GetFileName($filePath)
      $success = $false
      $name = $_.Name
      $jsonText = Get-Content -Raw -Path $filePath
      $jsonText = $jsonText -replace '\$\{tenantRootMgId\}', $using:TenantRootManagementGroupId
      $json = $jsonText | ConvertFrom-Json -AsHashtable
      Write-Host "[PolicySet][Start] $name ($fileName)"
      # Build ARM parameter file shape
      $paramsArm = @{
        parameters = @{
          policySetJson = @{ value = $json }
          baseName      = @{ value = $name }
        }
      }
      $tmp = New-TemporaryFile
      $paramsArm | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding UTF8
      $maxAttempts = 3
      for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        az deployment mg create `
          --management-group-id $using:TenantRootManagementGroupId `
          --name "policyset-$($name)" `
          --location $using:Location `
          --template-file "$using:PSScriptRoot/../infra/bicep/modules/policySetDefinitionFromFile.bicep" `
          --parameters @$tmp `
          --only-show-errors `
          --output none
        if ($LASTEXITCODE -eq 0) { $success = $true; break }
        if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds (2 * $attempt) }
      }
      if ($success) { Write-Host "[PolicySet][Success] $name" } else { Write-Host "[PolicySet][Failed] $name" }
      [pscustomobject]@{ Type='PolicySet'; Name=$name; File=$filePath; Succeeded=$success }
    } -ThrottleLimit $ThrottleLimit
  } else {
    foreach ($item in $policySetsToDeploy) {
      $filePath = $item.File
      $fileName = [System.IO.Path]::GetFileName($filePath)
      $name = $item.Name
      $jsonText = Get-Content -Raw -Path $filePath
      # Replace tokens for tenant root mg id in initiative
      $jsonText = $jsonText -replace '\$\{tenantRootMgId\}', $TenantRootManagementGroupId
      $json = $jsonText | ConvertFrom-Json -AsHashtable
  Write-Host "[PolicySet][Start] $name ($fileName)"
      # Build ARM parameter file shape
      $paramsArm = @{
        parameters = @{
          policySetJson = @{ value = $json }
          baseName      = @{ value = $name }
        }
      }
      $tmp = New-TemporaryFile
      $paramsArm | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding UTF8
      $success = $false
      $maxAttempts = 3
      for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        az deployment mg create `
          --management-group-id $TenantRootManagementGroupId `
          --name "policyset-$($name)" `
          --location $Location `
          --template-file "$PSScriptRoot/../infra/bicep/modules/policySetDefinitionFromFile.bicep" `
          --parameters @$tmp `
          --only-show-errors `
          --output none
        if ($LASTEXITCODE -eq 0) { $success = $true; break }
        if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds (2 * $attempt) }
      }
      if ($success) { Write-Host "[PolicySet][Success] $name" } else { Write-Host "[PolicySet][Failed] $name" }
      $policySetResults += [pscustomobject]@{ Type='PolicySet'; Name=$name; File=$filePath; Succeeded=$success }
    }
  }
}

# Final summary
$polCount  = ($policyResults | Measure-Object | Select-Object -ExpandProperty Count)
$polOk     = ($policyResults | Where-Object { $_.Succeeded } | Measure-Object | Select-Object -ExpandProperty Count)
$polFail   = $polCount - $polOk
$setCount  = ($policySetResults | Measure-Object | Select-Object -ExpandProperty Count)
$setOk     = ($policySetResults | Where-Object { $_.Succeeded } | Measure-Object | Select-Object -ExpandProperty Count)
$setFail   = $setCount - $setOk

Write-Host "================ Deployment Summary ================"
if ($Mode -in @('Policies','Both')) {
  Write-Host ("Policies: Total={0} Succeeded={1} Failed={2}" -f $polCount, $polOk, $polFail)
  if ($polFail -gt 0) {
    ($policyResults | Where-Object { -not $_.Succeeded }) | ForEach-Object { Write-Host ("  - FAILED: {0} ({1})" -f $_.Name, $_.File) }
  }
}
if ($Mode -in @('PolicySets','Both')) {
  Write-Host ("Policy Sets: Total={0} Succeeded={1} Failed={2}" -f $setCount, $setOk, $setFail)
  if ($setFail -gt 0) {
    ($policySetResults | Where-Object { -not $_.Succeeded }) | ForEach-Object { Write-Host ("  - FAILED: {0} ({1})" -f $_.Name, $_.File) }
  }
}

if ( ($polFail + $setFail) -gt 0 ) {
  Write-Host "One or more deployments failed. See details above." -ForegroundColor Red
  exit 1
} else {
  Write-Host "All deployments completed successfully."
}
