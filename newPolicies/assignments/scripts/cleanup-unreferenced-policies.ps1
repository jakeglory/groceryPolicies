param(
  [string] $PolicySetFile = "$PSScriptRoot/../definitions/policySetDefinitions/Enforce-EncryptTransit_20241211.alz_policy_set_definition.json",
  [string] $PolicyDefinitionsFolder = "$PSScriptRoot/../definitions/policyDefinitions",
  [switch] $Execute
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $PolicySetFile)) { throw "Policy set file not found: $PolicySetFile" }
if (-not (Test-Path -Path $PolicyDefinitionsFolder)) { throw "Policy definitions folder not found: $PolicyDefinitionsFolder" }

Write-Host "Reading policy set from: $PolicySetFile"
$policySet = Get-Content -Raw -Path $PolicySetFile | ConvertFrom-Json -AsHashtable

if (-not $policySet.properties -or -not $policySet.properties.policyDefinitions) {
  throw "Invalid policy set JSON: properties.policyDefinitions not found"
}

# Collect custom policy definition names referenced by the initiative (MG-scoped custom definitions)
$keepNames = New-Object System.Collections.Generic.HashSet[string]
foreach ($pd in $policySet.properties.policyDefinitions) {
  $id = [string]$pd.policyDefinitionId
  if ([string]::IsNullOrWhiteSpace($id)) { continue }

  # Match MG-scoped custom definition names
  if ($id -match "/providers/Microsoft.Management/managementGroups/[^/]+/providers/Microsoft.Authorization/policyDefinitions/([^/]+)$") {
    [void]$keepNames.Add($Matches[1])
  }
}

Write-Host "Custom definition names referenced by policy set (keep set):"
$keepNames | Sort-Object | ForEach-Object { Write-Host "  - $_" }

# Discover candidate JSON files under policyDefinitions
$files = Get-ChildItem -Path $PolicyDefinitionsFolder -Filter *.json -File -Recurse

# Helper: derive policy name from filename
function Get-PolicyNameFromFile([IO.FileInfo] $file) {
  $base = [string]$file.BaseName
  # Strip known suffixes like .alz_policy_definition or .policy
  $name = $base -replace "\.alz_policy_definition$", '' -replace "\.policy$", ''
  return $name
}

$toDelete = @()
$toKeep = @()
foreach ($f in $files) {
  $name = Get-PolicyNameFromFile $f
  if ($keepNames.Contains($name)) { $toKeep += $f.FullName } else { $toDelete += $f.FullName }
}

Write-Host "\nFiles to KEEP ($($toKeep.Count)):" -ForegroundColor Green
$toKeep | Sort-Object | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }

Write-Host "\nFiles to DELETE ($($toDelete.Count)):" -ForegroundColor Yellow
$toDelete | Sort-Object | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }

if (-not $Execute) {
  Write-Host "\nDry run only. Re-run with -Execute to apply deletions." -ForegroundColor Cyan
  return
}

Write-Host "\nDeleting $($toDelete.Count) file(s)..." -ForegroundColor Red
foreach ($path in $toDelete) {
  try {
    Remove-Item -LiteralPath $path -Force
    Write-Host "Deleted: $path" -ForegroundColor Red
  } catch {
    Write-Warning "Failed to delete: $path -> $($_.Exception.Message)"
  }
}

Write-Host "\nCleanup complete." -ForegroundColor Green
