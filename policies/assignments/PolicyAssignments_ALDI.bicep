targetScope = 'managementGroup'

@allowed([
  'build'
  'dev'
  'prd'
])
param stage string = 'dev'
param location string = 'westeurope'

var stageSettings = {
  build: {
    topLevelManagementGroupPrefix: 'build-mg'
    mgmtSubscriptionId: 'ac084e26-de58-47e4-92d4-0da6414956d8' // we are using only the prod mgmt subscription (used for LAW and LAWSA)
    lawName: 'log-we-prod-logmanagementworkspace' // Prod Resource
    lawRG: 'rg-logmanagementworkspace-prod'// Prod Resource
    lawSA: 'st0we0prod0law6aefc10b54' // Prod Resource
    connectivitySubscriptionId: '8406eed5-3171-437f-90bf-184f698e5fd7' // we are using only the prod connectiviy subscription (used for DDoS Plan)
    connectivityRGDdosPlan: 'rg-de-ohg-ats-tf-prod-ddos' // Prod Resource
    connectivityDdosPlanName: 'ddos-protection-std' // Prod Resource
  }
  dev: {
    topLevelManagementGroupPrefix: 'dev-mg'
    mgmtSubscriptionId: 'ac084e26-de58-47e4-92d4-0da6414956d8' // we are using only the prod mgmt subscription (used for LAW and LAWSA)
    lawName: 'log-we-prod-logmanagementworkspace' // Prod Resource
    lawRG: 'rg-logmanagementworkspace-prod'// Prod Resource
    lawSA: 'st0we0prod0law6aefc10b54' // Prod Resource
    connectivitySubscriptionId: '8406eed5-3171-437f-90bf-184f698e5fd7' // we are using only the prod connectiviy subscription (used for DDoS Plan)
    connectivityRGDdosPlan: 'rg-de-ohg-ats-tf-prod-ddos' // Prod Resource
    connectivityDdosPlanName: 'ddos-protection-std' // Prod Resource
    //enforcementMode: 'DoNotEnforce' //temporary all (new) policies are overridden with DoNotEnforce, this should be deprecated in the future when the new policies are used (change enforcement mode in module to the json file)
  }
  prd: {
    topLevelManagementGroupPrefix: 'mg'
    mgmtSubscriptionId: 'ac084e26-de58-47e4-92d4-0da6414956d8'
    lawName: 'log-we-prod-logmanagementworkspace'
    lawRG: 'rg-logmanagementworkspace-prod'
    lawSA: 'st0we0prod0law6aefc10b54'
    connectivitySubscriptionId: '8406eed5-3171-437f-90bf-184f698e5fd7'
    connectivityRGDdosPlan: 'rg-de-ohg-ats-tf-prod-ddos'
    connectivityDdosPlanName: 'ddos-protection-std'
    //enforcementMode: 'DoNotEnforce' //temporary all (new) policies are overridden with DoNotEnforce, this should be deprecated in the future when the new policies are used (change enforcement mode in module to the json file)
  }
}

// We are using PROD LAW for all environments
resource resLogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2021-12-01-preview' existing = {
  name: stageSettings[stage].lawName
  scope: resourceGroup(stageSettings[stage].mgmtSubscriptionId, stageSettings[stage].lawRG)
}
// We are using PROD DDoS Plan for all environments
resource resDdos 'Microsoft.Network/ddosProtectionPlans@2022-01-01' existing = {
  name: stageSettings[stage].connectivityDdosPlanName
  scope: resourceGroup(stageSettings[stage].connectivitySubscriptionId, stageSettings[stage].connectivityRGDdosPlan)
}
// We are using PROD SA for all environments
resource resStorageAccountLAW 'Microsoft.Storage/storageAccounts@2021-09-01' existing = {
  name: stageSettings[stage].lawSA
  scope: resourceGroup(stageSettings[stage].mgmtSubscriptionId, stageSettings[stage].lawRG)
}

// Getting IDs from resources
var logAnalyticsWorkspaceResourceId = resLogAnalyticsWorkspace.id
var ddosProtectionPlanId = resDdos.id
var lawSaId = resStorageAccountLAW.id

// creating management group root name
var intRoot = '${stageSettings[stage].topLevelManagementGroupPrefix}-aldi'
var topLevelManagementGroupResourceId = '/providers/Microsoft.Management/managementGroups/${intRoot}'

// Array with all custom policy assignments json files
var customPolicyAssignments = [
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Allowed-Locations'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Allowed-Locations.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Audit-AzureBackup'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Audit-AzureBackup.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Audit-AzureEventHubSettings'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Audit-AzureEHSettings.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Audit-KeyVaultSecuritySettings'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Audit-KVSecSettings.json'))
  }
//  {
//     definitionId: '/providers/Microsoft.Authorization/policySetDefinitions/8d723fb6-6680-45be-9d37-b1a4adb52207'
//     libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deploy-ResLogsToWEuSA.json'))
//  }
//  {
//    definitionId: '/providers/Microsoft.Authorization/policySetDefinitions/8d723fb6-6680-45be-9d37-b1a4adb52207'
//    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deploy-ResLogsToNEuSA.json'))
//  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Audit-SQLSettings'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Audit-SQLSettings.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-privateDnsZoneConfigsNew'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deploy-privateDnsZoneConfigsML.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-PublicAccess'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-PublicAccess.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-PublicIPs'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-PublicIPs-mgIdentity.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-PublicIPs'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-PublicIPs-mgLandingZones.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-PublicIPs'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-PublicIPs-mgManagement.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-VNETPeerSandboxes'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-VNETPeerSandboxes.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-Budget'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deploy-Budget-SBXSub.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-privateDnsZoneConfigs'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deploy-PrivDnsZoneConf.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Enable-DDoS-VNET'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Enable-DDoS-VNET-mgonlin.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Enable-DDoS-VNET'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Enable-DDoS-VNET-mgplatf.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Enforce-KeyVault-Security'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Enforce-KeyVault-Security.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Enforce-PlatformTags'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Enforce-PlatformTags.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-PublicPaaSEndpoints'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_es_deny_public_endpoints.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-MDFC-Config'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_es_deploy_mdfc_config.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-Diagnostics-LogAnalytics'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_es_deploy_resource_diag.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Enforce-EncryptTransit'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_es_enforce_tls_ssl.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Configure-Audit-StorageAccountSettings'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Set-StorageSettings.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Configure-MachineLearning-Security'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Configure-MLSecuritySettings.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Config-PrivateDNSopenAI'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Configure-PrivateDNSopenAI.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-ResourceDeletion'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-ResourceDeletionLAW.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-ResourceDeletion'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-ResourceDeletionLDCR.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-ResourceDeletion'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-ResourceDeletionWDCR.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-Public-DNS-Zones'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-PublicDNS-mgLandingZones.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-privateDnsZoneConfigs'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deploy-PrivDnsZoneConf_SAP.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-SpecificResourceDeployment'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-BastionDeploymentCORP.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-SpecificResourceDeployment'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-BastionDeploymentSAP.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-SpecificResourceDeployment'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Deny-DDoSProtection.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Conf-ActivLog-Export'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Configure_Activity_Log_Export.json'))
  }
  {
    definitionId: '${topLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Config-SecDCRwithAMA'
    libDefinition: json(loadTextContent('./lib/policy_assignments/policy_assignment_Configure_SecurityDCRandAMA.json'))
  }
]

//Modules - Policy Assignments //Temporary only audit / DoNotEnforce
  module mPolicyAssignmentALZ 'br/modules:microsoft.authorization.policyassignments:1.3.56' = [for policyAssignment in customPolicyAssignments: {
  name: 'PolicyAssignment-${policyAssignment.libDefinition.name}'
  params: {
    name: policyAssignment.libDefinition.name
    location: location
    policyDefinitionId: policyAssignment.definitionId
    description: policyAssignment.libDefinition.properties.description
    displayName: policyAssignment.libDefinition.properties.displayName
    // Currently we are using the override parameter to set the policy to DoNotEnforce for all (new) policies. When the variable will be removed, the policy will be set to the mode which is defined in the json file. If there is no mode defined in the json file, the policy will be set to DoNotEnforce.
    enforcementMode: contains(stageSettings[stage], 'enforcementMode') ? stageSettings[stage].enforcementMode : contains(policyAssignment.libDefinition.properties, 'enforcementMode') ? policyAssignment.libDefinition.properties.enforcementMode : 'DoNotEnforce'
    identity: contains(policyAssignment.libDefinition, 'identity') ? policyAssignment.libDefinition.identity.type : 'SystemAssigned'
    metadata: contains(policyAssignment.libDefinition.properties, 'metadata') ? policyAssignment.libDefinition.properties.metadata : {}
    nonComplianceMessages: contains(policyAssignment.libDefinition.properties, 'nonComplianceMessages') ? policyAssignment.libDefinition.properties.nonComplianceMessages : []
    notScopes: contains(policyAssignment.libDefinition.properties, 'notScopes') ? policyAssignment.libDefinition.properties.notScopes : []
    roleDefinitionIds: contains(policyAssignment.libDefinition.properties, 'roleDefinitionIds') ? policyAssignment.libDefinition.properties.roleDefinitionIds : []

    // the manangement group ID has to be in the format without prefix. For example "aldi" this will result in "dev-mg-alid" ind DEV and "mg-aldi" in PROD
    managementGroupId:  contains(policyAssignment.libDefinition.scope, 'managementGroupId') ? '${stageSettings[stage].topLevelManagementGroupPrefix}-${policyAssignment.libDefinition.scope.managementGroupId}' : ''
    subscriptionId:     (contains(policyAssignment.libDefinition.scope, 'subscriptionIdBuild') && stage == 'build' ) ? policyAssignment.libDefinition.scope.subscriptionIdBuild : (contains(policyAssignment.libDefinition.scope, 'subscriptionIdDev') && stage == 'dev' ) ? policyAssignment.libDefinition.scope.subscriptionIdDev : (contains(policyAssignment.libDefinition.scope, 'subscriptionIdPrd') && stage == 'prd' ) ? policyAssignment.libDefinition.scope.subscriptionIdPrd : ''
    // if you want to use the resourceGroup scope, you need to also specify the subsciptionId
    resourceGroupName:  (contains(policyAssignment.libDefinition.scope, 'resourceGroupNameBuild') && stage == 'build' ) ? policyAssignment.libDefinition.scope.resourceGroupNameBuild : (contains(policyAssignment.libDefinition.scope, 'resourceGroupNameDev') && stage == 'dev' ) ? policyAssignment.libDefinition.scope.resourceGroupNameDev : (contains(policyAssignment.libDefinition.scope, 'resourceGroupNamePrd') && stage == 'prd' ) ? policyAssignment.libDefinition.scope.resourceGroupNamePrd : ''

    parameters: union(policyAssignment.libDefinition.properties.parameters, 
      (contains(policyAssignment.libDefinition.properties.parameters, 'logAnalytics') ? {
        logAnalytics: { value: logAnalyticsWorkspaceResourceId }
      } : {}), 
      (contains(policyAssignment.libDefinition.properties.parameters, 'ddosPlan') ? {
        ddosPlan: { value: ddosProtectionPlanId }
      } : {}), 
      (contains(policyAssignment.libDefinition.properties.parameters, 'vulnerability Assessments Storage Account ID') ? {
        'vulnerability Assessments Storage Account ID': { value: lawSaId }
      } : {}))
  }
}]

output oPolAssignALZ array = [for (policy, i) in customPolicyAssignments: {
	name: mPolicyAssignmentALZ[i].outputs.name
	resourceId: mPolicyAssignmentALZ[i].outputs.resourceId
	roleDefinitionIds: mPolicyAssignmentALZ[i].outputs.principalId
}]
