targetScope = 'managementGroup'

// Clean policy set (initiative) Bicep module: requires explicit fields
@description('Policy set (initiative) definition object parsed from JSON')
param policySetJson object
@description('Base name of the policy set (without version suffix)')
param baseName string
var policySetName = baseName

resource policySet 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: policySetName
  properties: {
    policyType: 'Custom'
    displayName: string(policySetJson.properties.displayName)
    description: string(policySetJson.properties.description)
    metadata: union(policySetJson.properties.metadata, {
      source: 'policy-as-code'
    })
    parameters: policySetJson.properties.parameters
    policyDefinitions: policySetJson.properties.policyDefinitions
  }
}

output policySetDefinitionId string = policySet.id
