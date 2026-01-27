function New-AzPolicyRemediation {

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $policySetToRemediateName,
    
        [Parameter(Mandatory = $true)]
        [string] $mgName,
    
        [Parameter(Mandatory = $false)]
        [bool] $simulateOnly = $true        
    )
    #Start an md log file so we can upload it to a pipeline run
    Start-Transcript -Path ".\transcript-$mgName.md" -UseMinimalHeader -WhatIf:$false
    Write-Verbose "Starting remediation for $mgName. This will need some time." -Verbose
    
    #Get Policies from Set
    try {
        Write-Verbose "Getting policies from set $policySetToRemediateName in $mgName" -Verbose
        $policySetToRemediate = Get-AzPolicySetDefinition -ManagementGroupName $mgName | Where-Object { $_.Name -eq $policySetToRemediateName }
        Write-Verbose "Found: $($policySetToRemediate.PolicySetDefinitionId)" -Verbose
        $policiesToRemediate = @()
        $policiesToRemediate = $policySetToRemediate.Properties.PolicyDefinitions | Select-Object -ExpandProperty policyDefinitionReferenceId
        if ($null -eq $policiesToRemediate) {
            throw
        }
        Write-Verbose "Found $($policiesToRemediate.Count) policies to remediate" -Verbose
    }
    catch {
        Write-Error "Could not find policy set $policySetToRemediateName in $mgName"
        Write-Error $_.Exception.Message
        $File = Stop-Transcript 
        get-item $($File.Replace('Transcript stopped, output file is ', '')) 
        Write-host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Remediate;]$($File.Replace('Transcript stopped, output file is ',''))" 
        exit 1
    }

    ####

    #Get PolicyStates
    try {
        Write-Verbose "Getting policy states from $mgName" -Verbose
        #$AzRemediatAblePolicies = Get-AzPolicyState -ManagementGroupName $mgName | Where-Object { $_.ComplianceState -eq "NonCompliant" -and ($_.PolicyDefinitionAction -eq "deployIfNotExists" -or $_.PolicyDefinitionAction -eq "modify") }
        $AzRemediatAblePolicies = Get-AzPolicyState -ManagementGroupName $mgName -Filter "(PolicyDefinitionAction eq 'modify' or PolicyDefinitionAction eq 'deployifnotexists') and ComplianceState eq 'NonCompliant'"
        if ($null -eq $AzRemediatAblePolicies) {
            throw
        }
        Write-Verbose "Found $($AzRemediatAblePolicies.Count) policies which are not compliant and could be remediated" -Verbose
    }
    catch {
        Write-Error "Could not get policy states from $mgName"
        Write-Error $_.Exception.Message
        $File = Stop-Transcript 
        get-item $($File.Replace('Transcript stopped, output file is ', '')) 
        Write-host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Remediate;]$($File.Replace('Transcript stopped, output file is ',''))" 
        exit 1
    }


    #Get the PolicyNames. BuiltIn Policie have a Guid so we get the proper name to compare with the whitelist
    try {
        Write-Verbose "Getting policy definitions" -Verbose
        $AzPolicies = @()
        foreach ($AzPolicy in $AzRemediatAblePolicies.PolicyDefinitionId | Select-Object -Unique) {
            $AzPolicies += Get-AzPolicyDefinition -Id $AzPolicy -ErrorAction Ignore
        }
        if ($null -eq $AzPolicies) {
            throw
        }
    }
    catch {
        Write-Error "Could not get policy definitions"
        Write-Error $_.Exception.Message
        $File = Stop-Transcript 
        get-item $($File.Replace('Transcript stopped, output file is ', '')) 
        Write-host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Remediate;]$($File.Replace('Transcript stopped, output file is ',''))" 
        exit 1
    }

    #Get The Assignemnts
    try {
        Write-Verbose "Getting policy assignments" -Verbose
        Update-AzConfig -DisplayBreakingChangeWarning $false #-AppliesTo Get-AzPolicyAssignment
        $AzPolicyAssignments = @()
        foreach ($AzPolicyAssignment in $AzRemediatAblePolicies.PolicyAssignmentId | Select-Object -Unique) {
            $AzPolicyAssignments += Get-AzPolicyAssignment -Id $AzPolicyAssignment -ErrorAction Ignore #We can ignore errors as states might still include assignments which are deleted
        }
        if ($null -eq $AzPolicyAssignments) {
            throw
        }
    }
    catch {
        Write-Error "Could not get policy assignments"
        Write-Error $_.Exception.Message
        $File = Stop-Transcript 
        get-item $($File.Replace('Transcript stopped, output file is ', '')) 
        Write-host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Remediate;]$($File.Replace('Transcript stopped, output file is ',''))" 
        exit 1
    }


    #Build an array with all information needed
    $PoliciesToHandle = @()
    Write-Verbose "Building array with all information needed" -Verbose
    foreach ($AzRemediatAblePolicy in $AzRemediatAblePolicies | Where-Object { $_.PolicyAssignmentId -in $AzPolicyAssignments.PolicyAssignmentId } | Group-Object -Property PolicyAssignmentId, PolicyDefinitionReferenceId ) {
        $ThisPolicyDefinition = $ThisAssignment = $null
        $ThisAssignment = $AzPolicyAssignments | Where-Object { $_.PolicyAssignmentId -eq $($AzRemediatAblePolicy.Group.PolicyAssignmentId | Select-Object -Unique) }
        $ThisPolicyDefinition = $AzPolicies | Where-Object { $_.PolicyDefinitionId -eq $($AzRemediatAblePolicy.Group.PolicyDefinitionId | Select-Object -Unique) }
    
        $ThisPolicyToHandle = @{
            PolicyDisplayName           = $ThisPolicyDefinition.Properties.DisplayName
            AffectedResources           = $($AzRemediatAblePolicy.Group.ResourceId)
            PolicyDefinitionId          = $($AzRemediatAblePolicy.Group.PolicyDefinitionId | Select-Object -Unique)
            PolicyDefinitionReferenceId = $($AzRemediatAblePolicy.Group.PolicyDefinitionReferenceId | Select-Object -Unique)
            PolicyAssignmentScope       = $ThisAssignment.Properties.Scope
            PolicyAssignmentDisplayName = $ThisAssignment.Properties.DisplayName
            PolicyAssignmentId          = $($AzRemediatAblePolicy.Group.PolicyAssignmentId | Select-Object -Unique)
            #ToRemediate                 = $ThisPolicyDefinition.Properties.DisplayName -in $policiesToRemediate
            ToRemediate                 = $($AzRemediatAblePolicy.Group.PolicyDefinitionReferenceId | Select-Object -Unique) -in $policiesToRemediate
        }
        $PoliciesToHandle += $ThisPolicyToHandle    
    }


    $numbersOfRemediationTasks = 0
    #Iterate to groups. Remediation works on an assignment with a specific PolicydefinitionReferenceID. It is either this or we start remediation too often 
    Write-Verbose "Iterating to groups" -Verbose
    foreach ($PolicyByRemediationGroup in $PoliciesToHandle | Group-Object -Property ToRemediate) {
        #"# Remediation: $($PolicyByRemediationGroup.name)"
        if ($PolicyByRemediationGroup.name -eq $true) { #Disable if you want to have all policies in ouput (even not remediated)
            foreach ($PolicyByAssignmentGroup in $PolicyByRemediationGroup.Group | Group-Object -Property PolicyAssignmentId) {
                "## $($PolicyByAssignmentGroup.Group.PolicyAssignmentDisplayName | Select-Object -Unique)"
                "ID: $($PolicyByAssignmentGroup.Name)\"
                "Scope: $($PolicyByAssignmentGroup.Group.PolicyAssignmentScope | Select-Object -Unique)"
                foreach ($PolicyByPolicyDefinitionIdGroup in $PolicyByAssignmentGroup.Group | Group-Object -Property PolicyDefinitionId) {
                    "### $($PolicyByPolicyDefinitionIdGroup.Group.PolicyDisplayName | Select-Object -Unique)"
                    "ID: $($PolicyByPolicyDefinitionIdGroup.Name)\"
                    foreach ($PolicyByPolicyDefinitionReferenceIdGroup in $PolicyByPolicyDefinitionIdGroup.Group | Group-Object PolicyDefinitionReferenceId) {
                        "#### $($PolicyByPolicyDefinitionReferenceIdGroup.Name)"
                        "Affected Resources:"
                        $PolicyByPolicyDefinitionReferenceIdGroup.Group.AffectedResources | ForEach-Object { "- $_" }
                        "Count of affected resources: $($PolicyByPolicyDefinitionReferenceIdGroup.Group.AffectedResources.Count)"
                        if ($PolicyByPolicyDefinitionReferenceIdGroup.Group.ToRemediate -eq $true) {
                            $RemediationOptions = @{
                                Scope                       = $PolicyByPolicyDefinitionReferenceIdGroup.Group.PolicyAssignmentScope | Select-Object -Unique
                                Name                        = $(New-Guid).Guid
                                PolicyAssignmentId          = $PolicyByPolicyDefinitionReferenceIdGroup.Group.PolicyAssignmentId | Select-Object -Unique
                                PolicyDefinitionReferenceId = $PolicyByPolicyDefinitionReferenceIdGroup.Group.PolicyDefinitionReferenceId | Select-Object -Unique
                                ResourceDiscoveryMode       = "ExistingNonCompliant"
                                AsJob                       = !$simulateOnly
                                Whatif                      = $simulateOnly
                                Confirm                     = $false
                                ParallelDeploymentCount     = 20 #30 is max
                                ResourceCount               = 5000 #50.000 is max
                            }
                            '```pwsh'
                            $RemediationOptions
                            if ($PSCmdlet.ShouldProcess("$($RemediationOptions.PolicyDefinitionReferenceId): $($RemediationOptions.scope)", "Start-AzPolicyRemediation")) {
                                $ThisRemediationJob = Start-AzPolicyRemediation @RemediationOptions
                                if(-not $simulateOnly){
                                    $ThisRemediationJob | Wait-Job -ErrorAction SilentlyContinue 
                                    $ThisRemediationJob | Receive-Job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue
                                }
                                $numbersOfRemediationTasks++
                            }
                            '```'
                        }
                    }
                }
            }
        }
    }
    "###############################################"

    "# SUMMARY"
    "Created $numbersOfRemediationTasks remediation jobs"
    $File = Stop-Transcript 
    get-item $($File.Replace('Transcript stopped, output file is ', '')) 
    Write-host "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Remediate;]$($File.Replace('Transcript stopped, output file is ',''))" 
}
