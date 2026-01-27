//currently only used for ddos. In a later iteration this could be parameterized to support other assignments
param ddosPlanResourceName string
param principalId string 
param roleDefinitionId string

resource ddosPlan 'Microsoft.Network/ddosProtectionPlans@2022-05-01' existing = {
  name: ddosPlanResourceName
}

// we use direct resource instead of CARML because CARML does currently not support role assignments on Resource Level
resource rRoleAssignemtDdos 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(ddosPlanResourceName, 'ddosPlanContributor')
  properties: {
    principalId: principalId
    roleDefinitionId: roleDefinitionId
  }
  scope: ddosPlan
}

output ddosPlanName string = ddosPlan.name
output ddosPlanResourceId string = ddosPlan.id

output roleAssignmentId string = rRoleAssignemtDdos.id
output roleAssignmentName string = rRoleAssignemtDdos.name
