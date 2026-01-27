targetScope = 'managementGroup'

@allowed([
  'build'
  'dev'
  'prd'
])
param stage string = 'dev'

// all BUILD Exemption json files has to be defined here
var customPolicyExemptionsBuild = [
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_build/sub-ccoemgmt-build-DenyPublicAccessContainer.json'))  }
]

// all DEV Exemption json files has to be defined here
var customPolicyExemptionsDev = [

  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-aec-dev-DenyPublicAccessContainer.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-aec-dev-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-app-dev-fe-001-DenyPublicAccessContainer.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-app-dev-fe-001-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-oc-dev-be-001-DenyPublicAccessContainer.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-oc-dev-be-001-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-web-dev-001-DenyPublicAccessContainer.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-web-dev-001-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-web-dev-fe-001-DenyPublicAccessContainer.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-web-dev-fe-001-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-acoe-dev-AllowedLocationsSet.json'))  } 
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-azcomp-dev-KVSoftDelete.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-azcomponl-dev-KVSoftDelete.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-atran-dev-DenyPublicAccessSA.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-mlf-dev-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-mlf-dev-AllowedLocationsSet.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-dcs-dev-mgon-001-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-apim-dev-DenyPublicAccessKV.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_dev/sub-ccoemgmt-dev-DenyPublicAccessContainer.json'))  }
]
// all PROD Exemption json files has to be defined here
var customPolicyExemptionsPrd = [
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/mg-sap-Set-StorageSettings.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/mg-sap-custom-mg-aldi01.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-cnct-prod-wg-exd-001-allowedLocations.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-cnct-prod-wg-exd-001-allowedLocationsSet.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-lenovoblobstorage-prod-008-SA-Public-Access.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/sub-mia-prd-Deny-PublicIPs.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/sub-zba-int-SA-Public-Access.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/sub-zba-int-Set-StorageSettings.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/sub-zba-prd-SA-Public-Access.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/sub-zba-prd-Set-StorageSettings.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/sub-mlf-prd-MDfC-Storage.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-ccoe-prd-weu-pkrtmp-01-Deploy-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-nonpersadminvdi-prod-015-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-nonpersistentvdi-prod-003-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-persadminvdi-prod-016-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-persistentvdi-prod-004-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-pubappsbusiness-prod-005-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-pubappscentral-prod-007-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-pubappskv-prod-010-MDfC-Config.json'))  }
  {    libDefinition: json(loadTextContent('./lib/policy_exemptions_prd/rg-de-ohg-ngw-pubappslegacy-prod-011-MDfC-Config.json'))  }
]

//decide which exemptions to deploy based on stage
var customPolicyExemptions = stage == 'build' ? customPolicyExemptionsBuild : stage == 'dev' ? customPolicyExemptionsDev : customPolicyExemptionsPrd
//var customPolicyExemptions = stage == 'dev' ? customPolicyExemptionsDev : customPolicyExemptionsPrd

////Modules - Policy Exemption - ALDI Custom
module mPolicyExemption 'br/modules:microsoft.authorization.policyexemptions:1.2.48' = [for policyExemption in customPolicyExemptions: {
  //Deployments have a maximum of 64 characters (64-48=16)
  name: (length(policyExemption.libDefinition.name) >= 48 ) ? 'PolicyExemtpion-${substring(policyExemption.libDefinition.name, 0, 48)}' : 'PolicyExemtpion-${policyExemption.libDefinition.name}'
  params: {
    name: policyExemption.libDefinition.name
    policyAssignmentId: policyExemption.libDefinition.properties.policyAssignmentId
    description: policyExemption.libDefinition.properties.description
    displayName: policyExemption.libDefinition.properties.displayName
    metadata: contains(policyExemption.libDefinition.properties, 'metadata') ? policyExemption.libDefinition.properties.metadata : {} 

    exemptionCategory: contains(policyExemption.libDefinition.properties, 'exemptionCategory') ? policyExemption.libDefinition.properties.exemptionCategory : 'Waiver' 
    expiresOn: contains(policyExemption.libDefinition.properties, 'expiresOn') ? policyExemption.libDefinition.properties.expiresOn : '' 
    policyDefinitionReferenceIds: policyExemption.libDefinition.properties.policyDefinitionReferenceIds

    managementGroupId: contains(policyExemption.libDefinition.scope, 'managementGroupId') ? policyExemption.libDefinition.scope.managementGroupId : '' 
    subscriptionId: contains(policyExemption.libDefinition.scope, 'subscriptionId') ? policyExemption.libDefinition.scope.subscriptionId : '' 
    resourceGroupName: contains(policyExemption.libDefinition.scope, 'resourceGroupName') ? policyExemption.libDefinition.scope.resourceGroupName : '' 
  }
}]

output oPolExempt array = [for (policy, i) in customPolicyExemptions: {
  name: mPolicyExemption[i].outputs.name
  resourceId: mPolicyExemption[i].outputs.resourceId
  scope: mPolicyExemption[i].outputs.scope
}]
