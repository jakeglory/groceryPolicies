targetScope = 'managementGroup'

@allowed([
  'build'
  'dev'
  'prd'
])
param stage string = 'dev'

param connectivitySubscriptionIdPrd string = '8406eed5-3171-437f-90bf-184f698e5fd7' //sub-de-ohg-ats-dcs-cnct-prd
// we currently have only one ddos-protection Plan, so this is hardcoded for the moment
param ddosPlanResourceName string = 'ddos-protection-std'
param ddosPlanRGName string = 'rg-de-ohg-ats-tf-prod-ddos'
param privateDNSZonesRGName string = 'rg-cnct-prod-privatednszones'
param privateDNSZonesRGNameRoleDefinitionId string = '/providers/microsoft.authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7' //Private DNS Zone Contributor


//Hardocded (for the moment) values for the DNSPrivateZoneConfig 
var dnsPrivateZonePrincipalIDs =  [
  //'03ad5a9d-9edb-43dc-ae89-4c7908d0ac84' //providers/Microsoft.Management/managementGroups/dev-mg-corp/providers/Microsoft.Authorization/policyAssignments/Deploy-PrivDnsZoneConf
  '03ad5a9d-9edb-43dc-ae89-4c7908d0ac84' //providers/Microsoft.Management/managementGroups/dev-mg-corp/providers/Microsoft.Authorization/policyAssignments/Deploy-PrivDnsZoneConf
  //'2541b1b9-dc1a-4b8d-b230-a20497db3557' //providers/Microsoft.Management/managementGroups/mg-corp/providers/Microsoft.Authorization/policyAssignments/Deploy-PrivDnsZoneConf
  //'84f021ce-7242-4fa3-b91b-1d8b4f1af0b9' //providers/Microsoft.Management/managementGroups/mg-corp/providers/Microsoft.Authorization/policyAssignments/Deploy-PrivDnsZoneConf
  'a01debac-4e0e-4dbf-a9de-f6590f074c7b' //providers/Microsoft.Management/managementGroups/mg-corp/providers/Microsoft.Authorization/policyAssignments/Deploy-PrivDnsZoneConf
] 
//Hardocded (for the moment) values for the DNSPrivateZoneConfig 
var ddosPrincipalIDs =  [
  'b5ea04b3-3c85-4927-99ee-a0483e95f616' //providers/Microsoft.Management/managementGroups/dev-mg-online/providers/Microsoft.Authorization/policyAssignments/Enable-DDoS-VNET-mgonlin
  //''
] 
// will deploy all PolicyDefinitions and PolicySetDefinitions (Initiatives) on the management group dev-mg-aldi ord mg-aldi
module mPolicyDefinitions 'definitions/PolicyDefinitions_ALDI.bicep' = {
  name: 'Policy-Definitions'
  params: {
    stage: stage
  }
}
// will assign all PolicyAssignments on the management group given in the JSON file
module mPolicyAssignments 'assignments/PolicyAssignments_ALDI.bicep' = {
  dependsOn: [
    mPolicyDefinitions
  ]
  name: 'Policy-Assignments'
  params: {
    stage: stage
  }
}
// will deploy PolicyExemptions on any scope which is defined in the JSON file
// Policy Exemptions with an expired expiresOn date have to be removed from code
// module mPolicyExemptions 'exemptions/PolicyExemptions_ALDI.bicep' = {
//   dependsOn: [
//     mPolicyAssignments
//   ]
//   name: 'Policy-Exemptions'
//   params: {
//     stage: stage
//   }
// }

// Some PolicyAssignments need the Permissions which are in a different scope
module mRoleAssignmentDeployPrivDnsZoneConf 'br/modules:microsoft.authorization.roleassignments.resourcegroup:1.2.48' =  [for dnsPrivateZonePrincipalID in dnsPrivateZonePrincipalIDs: if (stage == 'prd') {
scope: resourceGroup(connectivitySubscriptionIdPrd, privateDNSZonesRGName) 
name: 'RA-DeployPrivDnsZoneConf-${dnsPrivateZonePrincipalID}'
params: {
principalId: dnsPrivateZonePrincipalID
roleDefinitionIdOrName: 'Private DNS Zone Contributor'
}
}]

// The dev managedIdentity needs permissions to prod ddos-plan
// we need an separate module for this, because the scope is different
module mRoleAssignmentDDoS 'roleAssignments/deploy.bicep' =  [for ddosPrincipalID in ddosPrincipalIDs: if (stage == 'prd') {
  scope: resourceGroup(connectivitySubscriptionIdPrd, ddosPlanRGName)
  name: 'DDOS-RoleAssignments-${ddosPrincipalID}'
  params: {
    principalId: ddosPrincipalID
    ddosPlanResourceName: ddosPlanResourceName
    roleDefinitionId: privateDNSZonesRGNameRoleDefinitionId
  }
}]

output oPolDefALZ array = mPolicyDefinitions.outputs.oPolDefALZ
output oPolSetdefALZ array = mPolicyDefinitions.outputs.oPolSetdefALZ

output oPolAssignALZArray array = mPolicyAssignments.outputs.oPolAssignALZ

// output oPolExemptArray array = mPolicyExemptions.outputs.oPolExempt
