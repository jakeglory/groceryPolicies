targetScope = 'subscription'

// Assign a policy (or policy set) at subscription scope using data from an assignment JSON file
@description('Assignment object parsed from JSON')
param assignmentJson object
@description('Customer name for display name composition')
param customerName string
@description('Domain for display name composition')
param domain string
@description('Location to assign for the policy assignment resource (helps when identity is set)')
param assignmentLocation string
@description('Display name of the policy or policy set to show in assignment display name')
param policyDisplayName string = ''

var _pdParts = split(string(assignmentJson.properties.policyDefinitionId), '/')
var _pdLastIndex = length(_pdParts) - 1
var _policyName = _pdParts[_pdLastIndex]
var _scopeRaw = string(assignmentJson.properties.scope)
var _scopeParts = split(_scopeRaw, '/')
var _scopePartsLen = length(_scopeParts)
var _scopeLastIndex = _scopePartsLen - 1
var _scopeDefault = subscription().subscriptionId
var _scopeLast = _scopePartsLen == 0 ? _scopeDefault : (_scopeParts[_scopeLastIndex] == '' ? (_scopePartsLen >= 2 ? _scopeParts[_scopeLastIndex - 1] : _scopeDefault) : _scopeParts[_scopeLastIndex])
var _policyTitle = length(trim(policyDisplayName)) > 0 ? policyDisplayName : _policyName
var displayName = '[${customerName}][${_scopeLast}][${domain}] ${_policyTitle}'
var _inName = string(assignmentJson.name)
var assignmentNameSafe = length(_inName) <= 24 ? _inName : '${substring(_inName, 0, 19)}-${substring(uniqueString(_inName), 0, 4)}'

resource assignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: assignmentNameSafe
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: displayName
    description: assignmentJson.properties.description
    policyDefinitionId: assignmentJson.properties.policyDefinitionId
    enforcementMode: assignmentJson.properties.enforcementMode
    nonComplianceMessages: assignmentJson.properties.nonComplianceMessages
    parameters: assignmentJson.properties.parameters
    metadata: union(assignmentJson.properties.metadata, {
      source: 'policy-as-code'
    })
  }
}

// Optional role assignments for the MI at the subscription scope
@description('Optional array of roleDefinitionIds to grant to the assignment managed identity at the subscription scope')
param roleDefinitionIds array = []

resource miRoleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for roleDefId in roleDefinitionIds: {
  name: guid(subscription().subscriptionId, assignment.name, roleDefId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefId)
    principalId: assignment.identity.principalId
    principalType: 'ServicePrincipal'
  }
}]

output policyAssignmentId string = assignment.id
