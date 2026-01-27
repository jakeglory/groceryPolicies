<#
.SYNOPSIS
Detects policy definitions which are not in the code and needs to be deleted from Azure.

.DESCRIPTION
The function compares the policy definitions in a given scope in Azure 
with definitions stored in a given local folder as JSON files. Then it returns all 
policy definitions which are not defined in the code.

.PARAMETER mgmtGroupId
Required. Management Group Id to scan.

.PARAMETER localDefinitionsPath
Required. Path of the folder where the policy definitions are stored as JSON files. 
The function doesn't serach in subfolders, just in the given folder.

.PARAMETER policyObjectType
Required. Object Type for which function should display results. Options: 'policyDefinitions', 'policySetDefinition', 'policyAssignments'.

.PARAMETER returnDiffOnly
Optional. Function returns full list of policy Objects present in Azure Portal if parameter is not present. If parameter is present returns only Objects to remove (not present in repo code but present in Azure Portal).

.EXAMPLE
Get-PolicyDefinitionsInfo -mgmtGroupId 'dev-mg-aldi' -localDefinitionsPath '\Aldi\AldiPolicies\AN-Azure-PlatformInfra\policies\definitions\lib\policy_definitions*' -policyObjectType 'policyAssignments' -returnDiffOnly

#>
function Get-PolicyDefinitionsInfo {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $mgmtGroupId,

        [Parameter(Mandatory = $true)]
        [string] $localDefinitionsPath,

        [ValidateSet('policyDefinitions', 'policySetDefinition', 'policyAssignments')]
        [Parameter(Mandatory = $true)]
        [string] $policyObjectType,

        [Parameter(Mandatory = $false)]
        [Switch] $returnDiffOnly)


    Write-Verbose ("Starting {0} comparison" -f $policyObjectType) -Verbose
    Write-Verbose ("Management Group: [{0}]" -f $mgmtGroupId) -Verbose
    Write-Verbose ("Local definitions folder: [{0}]" -f $localDefinitionsPath) -Verbose

    # verifying that the $localDefinitionsPath exists
    if (!(Test-Path -path $localDefinitionsPath)) {
        Write-Verbose ("Local {1} folder [{0}] not found" -f $localDefinitionsPath, $policyObjectType) -Verbose
        throw "Local {0} folder not found" -f $policyObjectType
    }
    
    # listing all json files in the folder $localDefinitionsPath
    $localDefinitionsFolderContent = Get-ChildItem -Path $(Join-Path $localDefinitionsPath '*.json') -File | Where-Object { $_.Name -notlike '*.parameters.json' }

    # throwing an exception if no JSON files found in the folder $localDefinitionsPath
    if ($localDefinitionsFolderContent.Count -eq 0) {
        Write-Verbose ("No {1} files found in the folder [{0}]" -f $localDefinitionsPath, $policyObjectType) -Verbose
        throw "No {0} files found locally" -f $policyObjectType
    }

    # Part1: reading definitions from all found json files into an array of definitions (objects)
    # creating an empty array
    $arrLocalDefinitions = @()

    # iterating through the json files in folder
    foreach ($jsonFile in $localDefinitionsFolderContent) {

        # building the full path of the file
        $filePath = Join-Path $localDefinitionsPath $jsonFile.Name
        # reading content of the json file and converting into an object
        $currentDefinition = Get-Content -Raw -Path $filePath | ConvertFrom-Json -Depth 99
        # adding the definition object to the array of definitions 
        $arrLocalDefinitions += $currentDefinition
    }
    Write-Verbose ("Number of {1} found locally: [{0}]" -f $arrLocalDefinitions.Count, $policyObjectType) -Verbose


    # Part2: reading all custom policy definitions from a given scope (Management Group) in Azure 
    # (ignoring definitions created on a subscription scope)
    
    switch ($policyObjectType) {
        policyDefinitions {
            $ResourceGraphQuery = "policyresources
            | where type =~'microsoft.authorization/policydefinitions'
            | where properties.policyType =~ 'Custom'
            | where isempty(subscriptionId) == true" 
        }
        policySetDefinition {
            $ResourceGraphQuery = "policyresources
            | where type =~'Microsoft.Authorization/PolicySetDefinitions'
            | where properties.policyType =~ 'Custom'
            | where isempty(subscriptionId) == true"
        }
        policyAssignments {
            $ResourceGraphQuery = "policyresources
            | where type =~'Microsoft.Authorization/PolicyAssignments'
            | where isempty(subscriptionId) == true"
        }
        Default {
            throw "incorrect policyObjectType: $policyObjectType"
        }
    }

    # running the query
    $policyDefinitionsAzure = Search-AzGraph -Query $ResourceGraphQuery -ManagementGroup $mgmtGroupId -First 1000

    Write-Verbose ("Number of {1} found in Azure: [{0}]" -f $policyDefinitionsAzure.Count, $policyObjectType) -Verbose

    # Part3: comparing local policy definitions (part 1) with the definitions found in Azure (part 2).
    # Storing definitions found in Azure, but not found locally into an array $arrDefinitionsToRemove 

    # creating an empty array
    $arrDefinitionsToRemove = @()
    $arrAllDefinitions = @()


    if ($mgmtGroupId.StartsWith('dev-')) {
        $mgmtPrefix = "dev-mg-"
    }
    else {
        $mgmtPrefix = "mg-"
    }
    
    if ( $policyObjectType -eq "policyAssignments") {
        $localDefinitionMap = @{}
        $arrLocalDefinitions | ForEach-Object {
            $managementGroupId = $null -ne $_.scope.managementgroupId ? $_.scope.managementgroupId : $_.properties.managementGroupId
            if ( $localDefinitionMap.ContainsKey("$mgmtPrefix$managementGroupId") ) {
                $localDefinitionMap["$mgmtPrefix$managementGroupId"] += $_.name
            }
            else {
                $localDefinitionMap["$mgmtPrefix$managementGroupId"] = @($_.name)
            }
        }
    }

    # iterating through the policy definitions found in Azure
    foreach ($policyDefinition in $policyDefinitionsAzure) {

        $defInfo = [pscustomobject] @{
            Name         = $policyDefinition.name
            Id           = $policyDefinition.id
            ExistsInCode = $policyObjectType -eq "policyAssignments" ? $localDefinitionMap[$policyDefinition.properties.scope.Split("/")[-1]] -contains $policyDefinition.name : $arrLocalDefinitions.name -contains $policyDefinition.name
        }
            
        if (-not $defInfo.ExistsInCode) {
            $arrDefinitionsToRemove += $defInfo
        }
        $arrAllDefinitions += $defInfo     
    }

    Write-Verbose ("Number of {1} to remove: [{0}]" -f $arrDefinitionsToRemove.count, $policyObjectType) -Verbose

    # returning the results
    if ($returnDiffOnly) {
        return $arrDefinitionsToRemove
    }
    else {
        return $arrAllDefinitions    
    }
}

# Get-PolicyDefinitionsInfo -mgmtGroupId 'dev-mg-aldi' -localDefinitionsPath '\PolicyComparisionLocal\AN-Azure-PlatformInfra\policies\definitions\lib\policy_definitions*' -policyObjectType 'policyDefinitions' -returnDiffOnly
# Get-PolicyDefinitionsInfo -mgmtGroupId 'dev-mg-aldi' -localDefinitionsPath '\PolicyComparisionLocal\AN-Azure-PlatformInfra\policies\definitions\lib\policy_set_definitions*' -policyObjectType 'policySetDefinition' -returnDiffOnly
# Get-PolicyDefinitionsInfo -mgmtGroupId 'dev-mg-aldi' -localDefinitionsPath '\PolicyComparisionLocal\AN-Azure-PlatformInfra\policies\assignments\lib\policy_assignments' -policyObjectType 'policyAssignments'

#Get-PolicyDefinitionsInfo -mgmtGroupId 'dev-mg-aldi' -localDefinitionsPath './assignments/lib/policy_assignments*' -policyObjectType 'policyAssignments'


function Get-PolicyExemptions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $mgmtGroupId,

        [Parameter(Mandatory = $true)]
        [string] $localDefinitionsPath)

    Write-Verbose ("Starting policy exemptions comparison") -Verbose
    Write-Verbose "Management Group: [$mgmtGroupId]" -Verbose
    Write-Verbose "Local definitions folder: [$localDefinitionsPath]" -Verbose
   
    #$mgmtGroupId = "mg-aldi"

    $allSubscriptons = Search-AzGraph -Query "ResourceContainers `
        | where type =~ 'microsoft.resources/subscriptions'" -ManagementGroup $mgmtGroupId -First 200
    $allPolicyExemptions = $allSubscriptons | ForEach-Object {
        Get-AzPolicyExemption -Scope $_.id -IncludeDescendent }


    ##DEBUG
    Write-Verbose "################################################" -Verbose
    Write-Verbose "Found following Subscriptions:" -Verbose
    $allSubscriptons | ForEach-Object { 
        
        Write-Verbose "$($_.name), $($_.subscriptionId) : $($_.properties.managementGroupAncestorsChain[0].name)" -Verbose }
    Write-Verbose "################################################" -Verbose

    if ($allPolicyExemptions) {
        Write-Verbose ("[$($allPolicyExemptions.Count)] policy exemptions found in AZURE") -Verbose
        $allPolicyExemptions | ForEach-Object { Write-Verbose ("policy exemption found in AZURE: [{0}]" -f $_.Properties.DisplayName) -Verbose }
    }
    else {
        Write-Verbose ("No policy exemptions found in AZURE") -Verbose
    }
   
    $localDefinitionsFolderContent = Get-ChildItem -Path $(Join-Path $localDefinitionsPath '*.json') -File

    $arrLocalDefinitions = @()
    foreach ($jsonFile in $localDefinitionsFolderContent) {

        # building the full path of the file
        $filePath = Join-Path $localDefinitionsPath $jsonFile.Name
        # reading content of the json file and converting into an object
        $currentDefinition = Get-Content -Raw -Path $filePath | ConvertFrom-Json -Depth 99
        # adding the definition object to the array of definitions 
        $arrLocalDefinitions += $currentDefinition
    }
    if ($arrLocalDefinitions) {
        Write-Verbose ("[$($arrLocalDefinitions.Count)] policy exemptions found in JSON") -Verbose
    }
    else {
        Write-Verbose ("No policy exemptions found in JSON") -Verbose
    }

    Write-Verbose "$($arrLocalDefinitions.properties.displayName)" -Verbose

    $onlyInAzure = @()
    foreach ($inAzure in $allPolicyExemptions) {

        $found = $false
        foreach ($inJson in $arrLocalDefinitions) {
        
            $found = $false

            # Only comparing Subscription scope exemptions, mg-scope is working with only Name currently
            # Could be added in future, also RG name check is optional! 
            if ( ($inJson.name -eq $inAzure.name) -and ($inJson.scope.subscriptionId -eq $inAzure.SubscriptionId)) {
                $found = $true
                Write-Verbose "Found in Azure and Code: $($inAzure.ResourceId)" -Verbose
                break
            }
            else {
                $found = $false
            }
        }
        if ($found -eq $false) {
            Write-Verbose "Not Found in Azure and Code: $($inAzure.ResourceId)" -Verbose
            $onlyInAzure += $inAzure
        }
    }
    Write-Verbose "Only in Azure:" -Verbose 
    $($onlyInAzure.ResourceId) | ConvertTo-Json | Write-Verbose  -Verbose 

    Write-Verbose "Number of policy exemptions found in ONLY Azure: [$($onlyInAzure.Count)]" -Verbose
    return $onlyInAzure
}

<#
.SYNOPSIS
Removes policy objets detected and returned by the function Get-PolicyDefinitionsInfo.

.DESCRIPTION
The function removes policy objets detected and returned by the function Get-PolicyDefinitionsInfo.

.PARAMETER definitionsToRemove
Required. Array of policy objects (policy definitions, policy set definitions or policy assignments) to remove.

.PARAMETER policyObjectType
Required. Object Type for which function should display results. Options: 'policyDefinitions', 'policySetDefinition', 'policyAssignments'.

.EXAMPLE
Remove-PolicyObject -definitionsToRemove $arrayOfDefinitions -policyObjectType 'policyDefinitions'

#>

function Remove-PolicyObject {
    # example function call for mg-aldi policy assignments to remove
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [Object[]] $definitionsToRemove,

        [ValidateSet('policyDefinitions', 'policySetDefinition', 'policyAssignments', 'policyExemptions')]
        [Parameter(Mandatory = $true)]
        [string] $policyObjectType,
        
        [Parameter(Mandatory = $true)]
        [string] $mgmtGroupId,
        
        [Parameter(Mandatory = $false)]
        [bool] $forceRemoval = $false,

        [Parameter(Mandatory = $false)]
        [array] $ignoredIds = $false
    )

    Write-Verbose ("Ignoring following IDs $ignoredIds") -Verbose
    if ($definitionsToRemove.Count -gt 0) {
        foreach ($definitionToRemove in $definitionsToRemove) {
            if (!$definitionToRemove.ExistsInCode -or $forceRemoval) {
                if ($ignoredIds -notcontains $definitionToRemove.id) {
                       
                    Write-Verbose ("Force Removal is set to [{0}]" -f $forceRemoval) -Verbose
                    switch ($policyObjectType) {
                        policyDefinitions {
                            # processing policy definitions
                            if ($PSCmdlet.ShouldProcess('Policy definition [{0}]' -f $definitionToRemove.id, 'Remove')) {
                                Write-Verbose ("Removing policy definition [{0}]" -f $definitionToRemove.id) -Verbose
                                Remove-AzPolicyDefinition -Id $definitionToRemove.id -Force
                            }
                        }
                        policySetDefinition {
                            # processing policy set definitions
                            if ($PSCmdlet.ShouldProcess('Policy set definition [{0}]' -f $definitionToRemove.id, 'Remove')) {
                                Write-Verbose ("Removing policy set definition [{0}]" -f $definitionToRemove.id) -Verbose
                                Remove-AzPolicySetDefinition -Id $definitionToRemove.id -Force
                            }
                        }
                        policyAssignments {
                            # processing policy assignments
                            
                            if ($PSCmdlet.ShouldProcess('Policy assignment [{0}]' -f $definitionToRemove.id, 'Remove')) {
                                try {
                                    Write-Verbose "Removing assigned Identity" -Verbose
                                    $ResourceGraphQuery = "policyresources
                                        | where type =~'Microsoft.Authorization/PolicyAssignments'
                                        | where id =~'$($definitionToRemove.id)'"
                                    $policyDefinitionsAzure = Search-AzGraph -Query $ResourceGraphQuery -ManagementGroup $mgmtGroupId -First 1000
                                    Get-AzRoleAssignment -Scope $policyDefinitionsAzure.properties.scope -ObjectId $policyDefinitionsAzure.identity.principalId | Remove-AzRoleAssignment 
                                }
                                catch {
                                    Write-Verbose "No Identity assigned" -Verbose
                                }
    
    
                                Write-Verbose ("Removing policy assignment [{0}]" -f $definitionToRemove.id) -Verbose
                                Remove-AzPolicyAssignment -Id $definitionToRemove.id
                            }
                        }
                        policyExemptions {
                            # processing policy exemptions
                            if ($PSCmdlet.ShouldProcess('Policy exemption [{0}]' -f $definitionToRemove.ResourceId, 'Remove')) {
                                Write-Verbose ("Removing policy exemption [{0}]" -f $definitionToRemove.ResourceId) -Verbose
                                Remove-AzPolicyExemption -Id $definitionToRemove.ResourceId -Verbose -Force
                            }
                        }
                        Default {
                            throw "incorrect policyObjectType: $policyObjectType"
                        }
                    }
                }
                else {
                    "Ignored ID: $($definitionToRemove.id)"
                }
            }
            else {
                throw "Attepting to remove object which exists in code: {0}" -f $definitionToRemove.id
            }
        }
    }
    return 0
}

<#
.SYNOPSIS
Compares policy definitions or policy set definitions between two management groups in Azure.

.DESCRIPTION
Compares policy definitions or policy set definitions or policy assignments between two management groups in Azure.
Then it returns all policy definitions which exist only in one of the mangement groups.

.PARAMETER policyObjectType
Required. Object Type for which function should display results. Options: 'policyDefinitions', 'policySetDefinition', 'policyAssignments'.

.PARAMETER returnDiffOnly
Optional. If parameter is present returns only policy objects which are present in one of the management groups, but not in the other one.
If not set, returns also policy objects, present in both mangement groups.

.EXAMPLE
Get-PolicyDefinitionsInfo -mgmtGroupId 'dev-mg-aldi' -localDefinitionsPath 'C:\Aldi\TestPolicyScript\AN-Azure-PlatformInfra\policies\policy_assignments' -policyObjectType 'policyAssignments' -returnDiffOnly

#>
function Compare-PolicyDefinitionsInfo {

    [CmdletBinding()]
    param (
        [ValidateSet('policyDefinitions', 'policySetDefinition', 'policyAssignments')]
        [Parameter(Mandatory = $true)]
        [string] $policyObjectType,

        [Parameter(Mandatory = $false)]
        [Switch] $returnDiffOnly)


    $mgmtGroupIdPrd = 'mg-aldi'
    $mgmtGroupIdDev = 'dev-mg-aldi'

    Write-Verbose ("Starting {0} comparison" -f $policyObjectType) -Verbose
    Write-Verbose ("Management Group 1: [{0}]" -f $mgmtGroupIdPrd) -Verbose
    Write-Verbose ("Management Group 2: [{0}]" -f $mgmtGroupIdDev) -Verbose

    # Part1: reading all custom policy definitions from a given scopes ($mgmtGroupIdPrd and $mgmtGroupIdDev) in Azure 
    # (ignoring definitions created on a subscription scope)
    
    # creating a Azure Resource Graph query
    switch ($policyObjectType) {
        policyDefinitions {
            $ResourceGraphQuery = "policyresources
            | where type =~'microsoft.authorization/policydefinitions'
            | where properties.policyType =~ 'Custom'
            | where isempty(subscriptionId) == true
            | where id contains 'managementGroups/<MgmtGr>'"
        }
        policySetDefinition {
            $ResourceGraphQuery = "policyresources
            | where type =~'Microsoft.Authorization/PolicySetDefinitions'
            | where properties.policyType =~ 'Custom'
            | where isempty(subscriptionId) == true
            | where id contains 'managementGroups/<MgmtGr>'"
        }
        policyAssignments {
            $ResourceGraphQuery = "policyresources
            | where type =~'Microsoft.Authorization/PolicyAssignments'
            | where isempty(subscriptionId) == true"
        }
        Default {
            throw "incorrect policyObjectType: $policyObjectType"
        }
    }

    # running the query
    if ($policyObjectType -eq 'policyAssignments') {
        $policyDefinitionsAzurePrd = Search-AzGraph -Query $ResourceGraphQuery -ManagementGroup $mgmtGroupIdPrd -First 1000
        $policyDefinitionsAzureDev = Search-AzGraph -Query $ResourceGraphQuery -ManagementGroup $mgmtGroupIdDev -First 1000
    }
    else {
        $policyDefinitionsAzurePrd = Search-AzGraph -Query $ResourceGraphQuery.Replace('<MgmtGr>', $mgmtGroupIdPrd) -ManagementGroup $mgmtGroupIdPrd -First 1000
        $policyDefinitionsAzureDev = Search-AzGraph -Query $ResourceGraphQuery.Replace('<MgmtGr>', $mgmtGroupIdDev) -ManagementGroup $mgmtGroupIdDev -First 1000
    }

    # creating a "CompareId", a propety ba
    foreach ($assignment in $policyDefinitionsAzurePrd) {
        $assignment | Add-Member -MemberType NoteProperty -Name 'CompareId' -Value $assignment.id
    }
    foreach ($assignment in $policyDefinitionsAzureDev) {
        $assignment | Add-Member -MemberType NoteProperty -Name 'CompareId' -Value $assignment.id.Replace('managementGroups/dev-', 'managementGroups/')
    }

    Write-Verbose ("Number of {0} found in the Management Group 1 [{1}]: [{2}]" -f $policyObjectType, $mgmtGroupIdPrd, $policyDefinitionsAzurePrd.Count) -Verbose
    Write-Verbose ("Number of {0} found in the Management Group 2 [{1}]: [{2}]" -f $policyObjectType, $mgmtGroupIdDev, $policyDefinitionsAzureDev.Count) -Verbose

    #region DEBUG
    Write-Verbose ("######DEBUG OUTPUT PROD: ") -Verbose
    foreach ($pol in $policyDefinitionsAzurePrd) {
        Write-Host ($pol.id) 
    }
   

    Write-Verbose ("######DEBUG OUTPUT DEV: ") -Verbose
    foreach ($pol in $policyDefinitionsAzureDev) {
        Write-Host ($pol.id) 
    }
    #endregion



    $arrResults = Compare-Object -ReferenceObject $policyDefinitionsAzureDev.CompareId -DifferenceObject $policyDefinitionsAzurePrd.CompareId -IncludeEqual

    # returning the results
    if ($returnDiffOnly) {
        return $arrResults | Where-Object { $_.SideIndicator -ne "==" }
    }
    else {
        return $arrResults    
    }
}


# $result = Compare-PolicyDefinitionsInfo -policyObjectType policyAssignments
# $mgmtGroupIdPrd = '=>' #mg-aldi'
# $mgmtGroupIdDev  = '<=' #'dev-mg-aldi'

# $resultsmgmtGroupIdPrd = $result | Where-Object { $_.SideIndicator -eq $mgmtGroupIdPrd }
# $resultsmgmtGroupIdDev = $result | Where-Object { $_.SideIndicator -eq $mgmtGroupIdDev }
# $resultsMgmtGrBoth = $result | Where-Object { $_.SideIndicator -eq "==" }

# Write-Verbose ("Number of unique results in PROD: [{0}]" -f $resultsmgmtGroupIdPrd.Count ) -Verbose
# $resultsmgmtGroupIdPrd | Select-Object -ExpandProperty InputObject

# Write-Verbose ("Number of unique results in DEV: [{0}]" -f $resultsmgmtGroupIdDev.Count ) -Verbose
# $resultsmgmtGroupIdDev | Select-Object  -ExpandProperty InputObject

# Write-Verbose ("Number of results which are equal" -f $resultsMgmtGrBoth.Count ) -Verbose
# $resultsMgmtGrBoth | Select-Object -ExpandProperty InputObject
