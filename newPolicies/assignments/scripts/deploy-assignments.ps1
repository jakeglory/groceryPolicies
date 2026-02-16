param(
  [Parameter(Mandatory=$true)] [string] $ManagementGroupId,
  [Parameter(Mandatory=$true)] [string] $CustomerName,
  [Parameter(Mandatory=$true)] [string] $AssignmentsFolder,
  [string] $Location = 'westeurope',
  [int] $ThrottleLimit = 5
)

$ErrorActionPreference = 'Stop'

Write-Host "Deploying assignments to MG: $ManagementGroupId"
Write-Host "Assignments folder: $AssignmentsFolder"
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

if (-not (Test-Path -Path $AssignmentsFolder)) {
  Write-Host "Assignments folder not found: $AssignmentsFolder. Skipping."
  return
}

$assignments = Get-ChildItem -Path $AssignmentsFolder -Filter *.json -Recurse -ErrorAction SilentlyContinue

if (-not $assignments -or $assignments.Count -eq 0) {
  Write-Host "No assignment files found in $AssignmentsFolder. Skipping."
  return
}

$supportsParallel = ($PSVersionTable.PSVersion.Major -ge 7)
if ($supportsParallel) {
  Write-Host "Parallel execution enabled with ThrottleLimit=$ThrottleLimit"
} else {
  Write-Host "Parallel execution not available. Running sequentially."
}

if ($supportsParallel) {
  $assignments | ForEach-Object -Parallel {
  # No filtering: process all assignment files
    $jsonText = Get-Content -Raw -Path $_.FullName
    $json = $jsonText | ConvertFrom-Json -AsHashtable

  # Resolve policy definition id, name, and whether it's a policy set (initiative)
    $policyDefId = [string]$json.properties.policyDefinitionId
    $isPolicySet = ($policyDefId -match '/policySetDefinitions/')
    # Parse definition scope from the policyDefinitionId (mg/sub/tenant-root)
    $defScopeType = 'tenant'
    $defMgId = ''
    $defSubId = ''
    $policyName = ''
    if ($policyDefId -match "/providers/Microsoft.Management/managementGroups/([^/]+)/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $defScopeType = 'mg'
      $defMgId = $Matches[1]
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/subscriptions/([0-9a-fA-F-]{36})/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $defScopeType = 'sub'
      $defSubId = $Matches[1]
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $defScopeType = 'tenant'
      $policyName = $Matches[2]
    } else {
      $policyName = ($policyDefId -split '/')[-1]
    }

  # Determine domain/category from local policy set JSON (preferred), then Azure, then fallback
  $domainForDisplay = ''
    # Resolve display name of the policy or policy set from local repository (prefer policy set)
    $policyDisplayName = ''
    try {
      if ($isPolicySet) {
  $policySetRoot = Join-Path $using:PSScriptRoot '../definitions/policySetDefinitions'
        $psFiles = Get-ChildItem -Path $policySetRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
        foreach ($f in $psFiles) {
          try {
            $psObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
            if ($psObj.name -and ($psObj.name -eq $policyName) -and $psObj.properties -and $psObj.properties.displayName) { $policyDisplayName = [string]$psObj.properties.displayName; break }
          } catch { }
        }
      }
      if (-not $isPolicySet -or -not $policyDisplayName) {
        # try policy definition display name
  $policyDefRoot = Join-Path $using:PSScriptRoot '../definitions/policyDefinitions'
        $pdFiles = Get-ChildItem -Path $policyDefRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
        foreach ($f in $pdFiles) {
          try {
            $pdObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
            if ($pdObj.name -and ($pdObj.name -eq $policyName) -and $pdObj.properties -and $pdObj.properties.displayName) { $policyDisplayName = [string]$pdObj.properties.displayName; break }
          } catch { }
        }
      }
    } catch { }

    # 1) Try local policy set JSON repository lookup by name
    if ($isPolicySet -and -not $domainForDisplay) {
      try {
  $policySetRoot = Join-Path $using:PSScriptRoot '../definitions/policySetDefinitions'
        $psFiles = Get-ChildItem -Path $policySetRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
        foreach ($f in $psFiles) {
          try {
            $psObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
            if ($psObj.name -and ($psObj.name -eq $policyName)) {
              if ($psObj.properties -and $psObj.properties.metadata -and $psObj.properties.metadata.category) {
                $domainForDisplay = [string]$psObj.properties.metadata.category
                break
              }
            }
          } catch { }
        }
      } catch { }
    }
  # No further fallback; do not override if missing

    $roleIds = @()
    if ($json.ContainsKey('roleDefinitionIds')) { $roleIds = $json.roleDefinitionIds }
  # Build ARM parameter file shape
    $paramsArm = @{
      parameters = @{
        assignmentJson    = @{ value = $json }
        managementGroupId = @{ value = $using:ManagementGroupId }
        customerName      = @{ value = $using:CustomerName }
        domain            = @{ value = $domainForDisplay }
        roleDefinitionIds = @{ value = $roleIds }
        assignmentLocation = @{ value = $using:Location }
  policyDisplayName = @{ value = $policyDisplayName }
      }
    }

    $tmp = New-TemporaryFile
    $paramsArm | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding UTF8
  # Determine scope from assignment JSON if provided
  $scope = $json.properties.scope
    if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "/providers/Microsoft.Management/managementGroups/$using:ManagementGroupId" }

  if ($scope -match "/providers/Microsoft.Management/managementGroups/(.+)$") {
      $mgId = $Matches[1]
      az deployment mg create `
        --management-group-id $mgId `
        --name "assign-$($json.name)-$mgId" `
        --location $using:Location `
        --template-file "$using:PSScriptRoot/../infra/bicep/modules/policyAssignmentFromFile.bicep" `
        --parameters @$tmp
  } elseif ($scope -match "/subscriptions/([0-9a-fA-F-]{36})($|/)") {
      $subId = $Matches[1]
      az deployment sub create `
        --subscription $subId `
        --name "assign-$($json.name)-$subId" `
        --location $using:Location `
        --template-file "$using:PSScriptRoot/../infra/bicep/modules/policyAssignmentFromFile.sub.bicep" `
        --parameters @$tmp
  } elseif ($scope -match "/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([^/]+)$") {
      $subId = $Matches[1]; $rg = $Matches[2]
      az deployment group create `
        --subscription $subId `
        --resource-group $rg `
        --name "assign-$($json.name)-$rg" `
        --template-file "$using:PSScriptRoot/../infra/bicep/modules/policyAssignmentFromFile.rg.bicep" `
        --parameters @$tmp
    } else {
      throw "Unsupported scope value: $scope"
    }
  } -ThrottleLimit $ThrottleLimit
} else {
  foreach ($file in $assignments) {
  # No filtering: process all assignment files
    $jsonText = Get-Content -Raw -Path $file.FullName
    $json = $jsonText | ConvertFrom-Json -AsHashtable

  # Resolve policy definition id, name, and whether it's a policy set (initiative)
    $policyDefId = [string]$json.properties.policyDefinitionId
    $isPolicySet = ($policyDefId -match '/policySetDefinitions/')
    # Parse definition scope from the policyDefinitionId (mg/sub/tenant-root)
    $defScopeType = 'tenant'
    $defMgId = ''
    $defSubId = ''
    $policyName = ''
    if ($policyDefId -match "/providers/Microsoft.Management/managementGroups/([^/]+)/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $defScopeType = 'mg'
      $defMgId = $Matches[1]
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/subscriptions/([0-9a-fA-F-]{36})/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $defScopeType = 'sub'
      $defSubId = $Matches[1]
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $defScopeType = 'tenant'
      $policyName = $Matches[2]
    } else {
      $policyName = ($policyDefId -split '/')[-1]
    }

  # Determine domain/category from local policy set JSON (preferred), then Azure, then fallback
  $domainForDisplay = ''
    # Resolve display name of the policy or policy set from local repository (prefer policy set)
    $policyDisplayName = ''
    try {
      if ($isPolicySet) {
  $policySetRoot = Join-Path $PSScriptRoot '../definitions/policySetDefinitions'
        $psFiles = Get-ChildItem -Path $policySetRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
        foreach ($f in $psFiles) {
          try {
            $psObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
            if ($psObj.name -and ($psObj.name -eq $policyName) -and $psObj.properties -and $psObj.properties.displayName) { $policyDisplayName = [string]$psObj.properties.displayName; break }
          } catch { }
        }
      }
      if (-not $isPolicySet -or -not $policyDisplayName) {
        # try policy definition display name
  $policyDefRoot = Join-Path $PSScriptRoot '../definitions/policyDefinitions'
        $pdFiles = Get-ChildItem -Path $policyDefRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
        foreach ($f in $pdFiles) {
          try {
            $pdObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
            if ($pdObj.name -and ($pdObj.name -eq $policyName) -and $pdObj.properties -and $pdObj.properties.displayName) { $policyDisplayName = [string]$pdObj.properties.displayName; break }
          } catch { }
        }
      }
    } catch { }
    # 1) Try local policy set JSON repository lookup by name
    if ($isPolicySet -and -not $domainForDisplay) {
      try {
  $policySetRoot = Join-Path $PSScriptRoot '../definitions/policySetDefinitions'
        $psFiles = Get-ChildItem -Path $policySetRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
        foreach ($f in $psFiles) {
          try {
            $psObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
            if ($psObj.name -and ($psObj.name -eq $policyName)) {
              if ($psObj.properties -and $psObj.properties.metadata -and $psObj.properties.metadata.category) {
                $domainForDisplay = [string]$psObj.properties.metadata.category
                break
              }
            }
          } catch { }
        }
      } catch { }
    }
  # No further fallback; do not override if missing

    $roleIds = @()
    if ($json.ContainsKey('roleDefinitionIds')) { $roleIds = $json.roleDefinitionIds }
    # Build ARM parameter file shape
    $paramsArm = @{
      parameters = @{
        assignmentJson    = @{ value = $json }
        managementGroupId = @{ value = $ManagementGroupId }
        customerName      = @{ value = $CustomerName }
        domain            = @{ value = $domainForDisplay }
        roleDefinitionIds = @{ value = $roleIds }
        assignmentLocation = @{ value = $Location }
  policyDisplayName = @{ value = $policyDisplayName }
      }
    }

    $tmp = New-TemporaryFile
    $paramsArm | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding UTF8
    # Determine scope from assignment JSON if provided
    $scope = $json.properties.scope
    if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId" }

    if ($scope -match "/providers/Microsoft.Management/managementGroups/(.+)$") {
      $mgId = $Matches[1]
      az deployment mg create `
        --management-group-id $mgId `
        --name "assign-$($json.name)-$mgId" `
        --location $Location `
        --template-file "$PSScriptRoot/../infra/bicep/modules/policyAssignmentFromFile.bicep" `
        --parameters @$tmp
    } elseif ($scope -match "/subscriptions/([0-9a-fA-F-]{36})($|/)") {
      $subId = $Matches[1]
      az deployment sub create `
        --subscription $subId `
        --name "assign-$($json.name)-$subId" `
        --location $Location `
        --template-file "$PSScriptRoot/../infra/bicep/modules/policyAssignmentFromFile.sub.bicep" `
        --parameters @$tmp
    } elseif ($scope -match "/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([^/]+)$") {
      $subId = $Matches[1]; $rg = $Matches[2]
      az deployment group create `
        --subscription $subId `
        --resource-group $rg `
        --name "assign-$($json.name)-$rg" `
        --template-file "$PSScriptRoot/../infra/bicep/modules/policyAssignmentFromFile.rg.bicep" `
        --parameters @$tmp
    } else {
      throw "Unsupported scope value: $scope"
    }
  }
}
