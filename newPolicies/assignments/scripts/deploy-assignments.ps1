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

function Get-PolicyNameFromDefinitionId {
  param(
    [string] $DefinitionId
  )

  if ([string]::IsNullOrWhiteSpace($DefinitionId)) { return '' }
  $parts = $DefinitionId -split '/'
  if (-not $parts -or $parts.Count -eq 0) { return '' }
  return [string]$parts[-1]
}

function Convert-RoleDefinitionIdToGuid {
  param(
    [string] $RoleDefinitionId
  )

  if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return $null }

  $value = [string]$RoleDefinitionId
  if ($value -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$') {
    return $Matches[1].ToLowerInvariant()
  }

  return $null
}

function Get-RoleDefinitionIdsFromObject {
  param(
    [object] $InputObject
  )

  $collected = New-Object System.Collections.Generic.List[string]

  function Invoke-TraverseRoleIds {
    param(
      [object] $Node,
      [System.Collections.Generic.List[string]] $Sink
    )

    if ($null -eq $Node) { return }

    if ($Node -is [System.Collections.IDictionary]) {
      if ($Node.Contains('roleDefinitionIds') -and $Node['roleDefinitionIds']) {
        foreach ($rid in @($Node['roleDefinitionIds'])) {
          if (-not [string]::IsNullOrWhiteSpace([string]$rid)) {
            $Sink.Add([string]$rid)
          }
        }
      }

      foreach ($value in $Node.Values) {
        Invoke-TraverseRoleIds -Node $value -Sink $Sink
      }
      return
    }

    if (($Node -is [System.Collections.IEnumerable]) -and -not ($Node -is [string])) {
      foreach ($item in $Node) {
        Invoke-TraverseRoleIds -Node $item -Sink $Sink
      }
      return
    }

    if ($Node.PSObject -and $Node.PSObject.Properties) {
      foreach ($property in $Node.PSObject.Properties) {
        Invoke-TraverseRoleIds -Node $property.Value -Sink $Sink
      }
    }
  }

  Invoke-TraverseRoleIds -Node $InputObject -Sink $collected
  return @($collected)
}

function Get-BuiltInPolicyRoleDefinitionIds {
  param(
    [string] $BuiltInPolicyId
  )

  $result = @()
  if ([string]::IsNullOrWhiteSpace($BuiltInPolicyId)) { return $result }

  $policyGuid = Convert-RoleDefinitionIdToGuid -RoleDefinitionId $BuiltInPolicyId
  if ([string]::IsNullOrWhiteSpace($policyGuid)) { return $result }

  try {
    $policyJson = az policy definition show --name $policyGuid -o json 2>$null
    if (-not [string]::IsNullOrWhiteSpace($policyJson)) {
      $policyObj = $policyJson | ConvertFrom-Json -AsHashtable
      $rawRoleIds = Get-RoleDefinitionIdsFromObject -InputObject $policyObj
      foreach ($rid in @($rawRoleIds)) {
        $roleGuid = Convert-RoleDefinitionIdToGuid -RoleDefinitionId ([string]$rid)
        if (-not [string]::IsNullOrWhiteSpace($roleGuid)) {
          $result += $roleGuid
        }
      }
    }
  } catch {
    Write-Host "Warning: Could not resolve built-in policy definition '$BuiltInPolicyId' for role extraction."
  }

  return @($result | Sort-Object -Unique)
}

# Build local lookups once (used by both sequential and parallel execution)
$policySetLookup = @{}
$policyDefinitionDisplayLookup = @{}
$policyDefinitionRoleLookup = @{}
$builtInPolicyRoleLookup = @{}

$policySetRoot = Join-Path $PSScriptRoot '../definitions/policySetDefinitions'
$policyDefRoot = Join-Path $PSScriptRoot '../definitions/policyDefinitions'

$policySetFiles = Get-ChildItem -Path $policySetRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
foreach ($f in $policySetFiles) {
  try {
    $psObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
    if (-not $psObj.name) { continue }

    $includedPolicyNames = @()
    $includedBuiltInPolicyIds = @()
    if ($psObj.properties -and $psObj.properties.policyDefinitions) {
      foreach ($psRef in @($psObj.properties.policyDefinitions)) {
        $refId = [string]$psRef.policyDefinitionId
        if ($refId -match '^/providers/Microsoft\.Authorization/policyDefinitions/[0-9a-fA-F-]{36}$') {
          $includedBuiltInPolicyIds += $refId
        }
        $refName = Get-PolicyNameFromDefinitionId -DefinitionId $refId
        if (-not [string]::IsNullOrWhiteSpace($refName)) {
          $includedPolicyNames += $refName
        }
      }
    }

    $policySetLookup[$psObj.name] = @{
      displayName = if ($psObj.properties -and $psObj.properties.displayName) { [string]$psObj.properties.displayName } else { '' }
      category = if ($psObj.properties -and $psObj.properties.metadata -and $psObj.properties.metadata.category) { [string]$psObj.properties.metadata.category } else { '' }
      policyNames = @($includedPolicyNames)
      builtInPolicyIds = @($includedBuiltInPolicyIds | Sort-Object -Unique)
    }
  } catch { }
}

$policyDefFiles = Get-ChildItem -Path $policyDefRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
foreach ($f in $policyDefFiles) {
  try {
    $pdObj = Get-Content -Raw -Path $f.FullName | ConvertFrom-Json -AsHashtable
    if (-not $pdObj.name) { continue }

    $policyDefinitionDisplayLookup[$pdObj.name] = if ($pdObj.properties -and $pdObj.properties.displayName) { [string]$pdObj.properties.displayName } else { '' }

    $guids = @()
    $rawRoleDefinitionIds = Get-RoleDefinitionIdsFromObject -InputObject $pdObj
    foreach ($rid in $rawRoleDefinitionIds) {
      $roleGuid = Convert-RoleDefinitionIdToGuid -RoleDefinitionId $rid
      if (-not [string]::IsNullOrWhiteSpace($roleGuid)) {
        $guids += $roleGuid
      }
    }

    $policyDefinitionRoleLookup[$pdObj.name] = @($guids | Sort-Object -Unique)
  } catch { }
}

# Resolve roleDefinitionIds for built-in policy definitions referenced by policy sets
$allBuiltInPolicyIds = @()
foreach ($ps in $policySetLookup.Values) {
  if ($ps.builtInPolicyIds) {
    $allBuiltInPolicyIds += @($ps.builtInPolicyIds)
  }
}

foreach ($builtInPolicyId in @($allBuiltInPolicyIds | Sort-Object -Unique)) {
  $builtInPolicyRoleLookup[$builtInPolicyId] = @(Get-BuiltInPolicyRoleDefinitionIds -BuiltInPolicyId $builtInPolicyId)
}

$supportsParallel = ($PSVersionTable.PSVersion.Major -ge 7)
if ($supportsParallel) {
  Write-Host "Parallel execution enabled with ThrottleLimit=$ThrottleLimit"
} else {
  Write-Host "Parallel execution not available. Running sequentially."
}

if ($supportsParallel) {
  $assignments | ForEach-Object {
    $policySetLookupLocal = $policySetLookup
    $policyDefinitionDisplayLookupLocal = $policyDefinitionDisplayLookup
    $policyDefinitionRoleLookupLocal = $policyDefinitionRoleLookup
    $builtInPolicyRoleLookupLocal = $builtInPolicyRoleLookup
    $managementGroupIdLocal = $ManagementGroupId
    $customerNameLocal = $CustomerName
    $locationLocal = $Location
    $psScriptRootLocal = $PSScriptRoot

  # No filtering: process all assignment files
    $jsonText = Get-Content -Raw -Path $_.FullName
    $json = $jsonText | ConvertFrom-Json -AsHashtable

  # Resolve policy definition id, name, and whether it's a policy set (initiative)
    $policyDefId = [string]$json.properties.policyDefinitionId
    $isPolicySet = ($policyDefId -match '/policySetDefinitions/')
    $policyName = ''
    if ($policyDefId -match "/providers/Microsoft.Management/managementGroups/([^/]+)/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/subscriptions/([0-9a-fA-F-]{36})/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $policyName = $Matches[2]
    } else {
      $policyName = ($policyDefId -split '/')[-1]
    }

  # Resolve display metadata from lookup tables
  $domainForDisplay = ''
    $policyDisplayName = ''
    if ($isPolicySet -and $policySetLookupLocal.ContainsKey($policyName)) {
      $psInfo = $policySetLookupLocal[$policyName]
      if ($psInfo.displayName) { $policyDisplayName = [string]$psInfo.displayName }
      if ($psInfo.category) { $domainForDisplay = [string]$psInfo.category }
    }
    if (-not $policyDisplayName -and $policyDefinitionDisplayLookupLocal.ContainsKey($policyName)) {
      $policyDisplayName = [string]$policyDefinitionDisplayLookupLocal[$policyName]
    }

    # Build effective roleDefinitionIds for assignment MI:
    # - explicit roleDefinitionIds on assignment JSON
    # - plus all roleDefinitionIds found in policy definitions included by the assigned policy set
    $roleIds = @()
    if ($json.ContainsKey('roleDefinitionIds')) {
      foreach ($rid in @($json.roleDefinitionIds)) {
        $value = [string]$rid
        if ($value -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$') {
          $roleIds += $Matches[1].ToLowerInvariant()
        }
      }
    }
    if ($isPolicySet -and $policySetLookupLocal.ContainsKey($policyName)) {
      $psInfo = $policySetLookupLocal[$policyName]
      foreach ($includedPolicyName in @($psInfo.policyNames)) {
        if ($policyDefinitionRoleLookupLocal.ContainsKey($includedPolicyName)) {
          $roleIds += @($policyDefinitionRoleLookupLocal[$includedPolicyName])
        }
      }
      foreach ($builtInPolicyId in @($psInfo.builtInPolicyIds)) {
        if ($builtInPolicyRoleLookupLocal.ContainsKey($builtInPolicyId)) {
          $roleIds += @($builtInPolicyRoleLookupLocal[$builtInPolicyId])
        }
      }
    }
    $roleIds = @($roleIds | Sort-Object -Unique)
  # Build ARM parameter file shape
    $paramsArm = @{
      parameters = @{
        assignmentJson    = @{ value = $json }
        managementGroupId = @{ value = $managementGroupIdLocal }
        customerName      = @{ value = $customerNameLocal }
        domain            = @{ value = $domainForDisplay }
        roleDefinitionIds = @{ value = $roleIds }
        assignmentLocation = @{ value = $locationLocal }
  policyDisplayName = @{ value = $policyDisplayName }
      }
    }

    $tmp = New-TemporaryFile
    $paramsArm | ConvertTo-Json -Depth 100 | Set-Content -Path $tmp -Encoding UTF8
  # Determine scope from assignment JSON if provided
  $scope = $json.properties.scope
    if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "/providers/Microsoft.Management/managementGroups/$managementGroupIdLocal" }

  if ($scope -match "/providers/Microsoft.Management/managementGroups/(.+)$") {
      $mgId = $Matches[1]
      az deployment mg create `
        --management-group-id $mgId `
        --name "assign-$($json.name)-$mgId" `
        --location $locationLocal `
        --template-file "$psScriptRootLocal/../infra/bicep/modules/policyAssignmentFromFile.bicep" `
        --parameters @$tmp
  } elseif ($scope -match "/subscriptions/([0-9a-fA-F-]{36})($|/)") {
      $subId = $Matches[1]
      az deployment sub create `
        --subscription $subId `
        --name "assign-$($json.name)-$subId" `
        --location $locationLocal `
        --template-file "$psScriptRootLocal/../infra/bicep/modules/policyAssignmentFromFile.sub.bicep" `
        --parameters @$tmp
  } elseif ($scope -match "/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([^/]+)$") {
      $subId = $Matches[1]; $rg = $Matches[2]
      az deployment group create `
        --subscription $subId `
        --resource-group $rg `
        --name "assign-$($json.name)-$rg" `
        --template-file "$psScriptRootLocal/../infra/bicep/modules/policyAssignmentFromFile.rg.bicep" `
        --parameters @$tmp
    } else {
      throw "Unsupported scope value: $scope"
    }
  }
} else {
  foreach ($file in $assignments) {
  # No filtering: process all assignment files
    $jsonText = Get-Content -Raw -Path $file.FullName
    $json = $jsonText | ConvertFrom-Json -AsHashtable

  # Resolve policy definition id, name, and whether it's a policy set (initiative)
    $policyDefId = [string]$json.properties.policyDefinitionId
    $isPolicySet = ($policyDefId -match '/policySetDefinitions/')
    $policyName = ''
    if ($policyDefId -match "/providers/Microsoft.Management/managementGroups/([^/]+)/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/subscriptions/([0-9a-fA-F-]{36})/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $policyName = $Matches[3]
    } elseif ($policyDefId -match "/providers/Microsoft.Authorization/(policySetDefinitions|policyDefinitions)/([^/]+)$") {
      $policyName = $Matches[2]
    } else {
      $policyName = ($policyDefId -split '/')[-1]
    }

  # Resolve display metadata from lookup tables
  $domainForDisplay = ''
    $policyDisplayName = ''
    if ($isPolicySet -and $policySetLookup.ContainsKey($policyName)) {
      $psInfo = $policySetLookup[$policyName]
      if ($psInfo.displayName) { $policyDisplayName = [string]$psInfo.displayName }
      if ($psInfo.category) { $domainForDisplay = [string]$psInfo.category }
    }
    if (-not $policyDisplayName -and $policyDefinitionDisplayLookup.ContainsKey($policyName)) {
      $policyDisplayName = [string]$policyDefinitionDisplayLookup[$policyName]
    }

    # Build effective roleDefinitionIds for assignment MI:
    # - explicit roleDefinitionIds on assignment JSON
    # - plus all roleDefinitionIds found in policy definitions included by the assigned policy set
    $roleIds = @()
    if ($json.ContainsKey('roleDefinitionIds')) {
      foreach ($rid in @($json.roleDefinitionIds)) {
        $roleGuid = Convert-RoleDefinitionIdToGuid -RoleDefinitionId ([string]$rid)
        if (-not [string]::IsNullOrWhiteSpace($roleGuid)) {
          $roleIds += $roleGuid
        }
      }
    }
    if ($isPolicySet -and $policySetLookup.ContainsKey($policyName)) {
      $psInfo = $policySetLookup[$policyName]
      foreach ($includedPolicyName in @($psInfo.policyNames)) {
        if ($policyDefinitionRoleLookup.ContainsKey($includedPolicyName)) {
          $roleIds += @($policyDefinitionRoleLookup[$includedPolicyName])
        }
      }
      foreach ($builtInPolicyId in @($psInfo.builtInPolicyIds)) {
        if ($builtInPolicyRoleLookup.ContainsKey($builtInPolicyId)) {
          $roleIds += @($builtInPolicyRoleLookup[$builtInPolicyId])
        }
      }
    }
    $roleIds = @($roleIds | Sort-Object -Unique)
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
