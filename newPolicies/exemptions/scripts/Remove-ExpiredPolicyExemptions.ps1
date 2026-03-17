[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Scope,

    [Parameter(Mandatory = $true)]
    [string]$EnvironmentName,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$RetentionDaysAfterExpiry = 30,

    [Parameter()]
    [bool]$DryRun = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-AzCli {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & az @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed with exit code $LASTEXITCODE. Command: az $($Arguments -join ' '). Details: $output"
    }

    return $output.Trim()
}

function Get-GraphScopeArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScopeResourceId
    )

    if ($ScopeResourceId -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)$') {
        return @('--management-groups', $Matches[1])
    }

    if ($ScopeResourceId -match '^/subscriptions/([^/]+)$') {
        return @('--subscriptions', $Matches[1])
    }

    throw "Unsupported scope format: '$ScopeResourceId'. Use a management group or subscription resource ID."
}

Write-Host "Starting policy exemption cleanup for environment '$EnvironmentName'."
Write-Host "Scope: $Scope"
Write-Host "RetentionDaysAfterExpiry: $RetentionDaysAfterExpiry"
Write-Host "DryRun: $DryRun"

$null = Invoke-AzCli -Arguments @('account', 'show', '--only-show-errors', '-o', 'none')

try {
    $null = Invoke-AzCli -Arguments @('extension', 'show', '--name', 'resource-graph', '--only-show-errors', '-o', 'none')
}
catch {
    Write-Host "Azure CLI resource-graph extension not found. Installing it now."
    $null = Invoke-AzCli -Arguments @('extension', 'add', '--name', 'resource-graph', '--only-show-errors', '-o', 'none')
}

$cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $RetentionDaysAfterExpiry)
$cutoffText = $cutoffUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
$graphScopeArguments = Get-GraphScopeArguments -ScopeResourceId $Scope

$query = @"
resources
| where type =~ 'microsoft.authorization/policyexemptions'
| extend expiresOnText = tostring(properties.expiresOn)
| where isnotempty(expiresOnText)
| extend expiresOn = todatetime(expiresOnText)
| where isnotnull(expiresOn)
| where expiresOn <= datetime($cutoffText)
| project id, name, expiresOnText, displayName = tostring(properties.displayName), exemptionCategory = tostring(properties.exemptionCategory)
| order by expiresOn asc
"@

Write-Host "Looking for policy exemptions with expiresOn older than $cutoffText ..."
$graphResponseText = Invoke-AzCli -Arguments (@('graph', 'query', '-q', $query, '--first', '1000', '--only-show-errors', '-o', 'json') + $graphScopeArguments)
$graphResponse = $graphResponseText | ConvertFrom-Json
$expiredExemptions = @($graphResponse.data)

if (($graphResponse.totalRecords | ForEach-Object { [int]$_ }) -gt $expiredExemptions.Count) {
    Write-Warning "Query returned only the first $($expiredExemptions.Count) records out of $($graphResponse.totalRecords). Increase paging support if this becomes a real scenario."
}

if ($expiredExemptions.Count -eq 0) {
    Write-Host "No policy exemptions found that expired more than $RetentionDaysAfterExpiry days ago."
    return
}

Write-Host "Found $($expiredExemptions.Count) expired policy exemption(s) eligible for cleanup."
foreach ($exemption in $expiredExemptions) {
    Write-Host "MATCH | Name=$($exemption.name) | Id=$($exemption.id) | ExpiresOn=$($exemption.expiresOnText)"
}

$deleted = New-Object System.Collections.Generic.List[object]
$failed = New-Object System.Collections.Generic.List[object]

foreach ($exemption in $expiredExemptions) {
    try {
        if ($DryRun) {
            $null = Invoke-AzCli -Arguments @('resource', 'show', '--ids', $exemption.id, '--only-show-errors', '-o', 'none')
            Write-Host "DRYRUN | Validated exemption '$($exemption.name)' with id '$($exemption.id)' for deletion"
            continue
        }

        Write-Host "Deleting exemption '$($exemption.name)' ..."
        $null = Invoke-AzCli -Arguments @('resource', 'delete', '--ids', $exemption.id, '--only-show-errors', '-o', 'none')
        $deleted.Add([PSCustomObject]@{
            Name = $exemption.name
            Id = $exemption.id
            ExpiresOn = $exemption.expiresOnText
        })
        Write-Host "DELETED | Name=$($exemption.name) | Id=$($exemption.id)"
    }
    catch {
        $failed.Add([PSCustomObject]@{
            Name = $exemption.name
            Id = $exemption.id
            ExpiresOn = $exemption.expiresOnText
            Reason = $_.Exception.Message
        })
        Write-Host "##vso[task.logissue type=error]Failed to delete policy exemption '$($exemption.name)': $($_.Exception.Message)"
    }
}

Write-Host "==============================================="
Write-Host "POLICY EXEMPTION CLEANUP SUMMARY - $EnvironmentName"
Write-Host "==============================================="
Write-Host "Eligible exemptions found: $($expiredExemptions.Count)"
Write-Host "Deleted exemptions: $($deleted.Count)"
Write-Host "Failed deletions: $($failed.Count)"
Write-Host "DryRun: $DryRun"
Write-Host "Cutoff: $cutoffText"
Write-Host "==============================================="

if ($DryRun) {
    if ($failed.Count -gt 0) {
        foreach ($failure in $failed) {
            Write-Host "DRYRUN-FAILED | Name=$($failure.Name) | Id=$($failure.Id) | ExpiresOn=$($failure.ExpiresOn) | Reason=$($failure.Reason)"
        }

        throw "Dry run detected $($failed.Count) policy exemption validation error(s) in environment '$EnvironmentName'."
    }

    Write-Host "Dry run completed successfully. No exemptions were deleted."
    return
}

if ($failed.Count -gt 0) {
    foreach ($failure in $failed) {
        Write-Host "FAILED | Name=$($failure.Name) | Id=$($failure.Id) | ExpiresOn=$($failure.ExpiresOn) | Reason=$($failure.Reason)"
    }

    throw "Policy exemption cleanup failed for $($failed.Count) exemption(s) in environment '$EnvironmentName'."
}

Write-Host "Policy exemption cleanup completed successfully for environment '$EnvironmentName'."
