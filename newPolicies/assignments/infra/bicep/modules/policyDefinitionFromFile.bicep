targetScope = 'managementGroup'

// Deploys a custom policy definition from a provided JSON object at Tenant Root MG scope
@description('Policy definition object parsed from JSON')
param policyJson object
@description('Base name of the policy definition')
param baseName string
var policyName = baseName

resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: policyName
  properties: {
    policyType: 'Custom'
    mode: string(policyJson.properties.mode)
    displayName: string(policyJson.properties.displayName)
    description: string(policyJson.properties.description)
    metadata: union(policyJson.properties.metadata, {
      source: 'policy-as-code'
    })
    parameters: policyJson.properties.parameters
    policyRule: policyJson.properties.policyRule
  }
}

output policyDefinitionId string = policyDef.id
