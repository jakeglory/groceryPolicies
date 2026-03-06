targetScope = 'resourceGroup'

@description('Name of the scheduled query alert rule.')
param alertName string = 'la-table-restore-alert'

@description('Azure region for the alert resource.')
param location string = resourceGroup().location

@description('Resource ID of the target Log Analytics workspace.')
param workspaceResourceId string

@description('Severity of the alert from 0 (Critical) to 4 (Verbose).')
@minValue(0)
@maxValue(4)
param severity int = 2

@description('How often the query runs (ISO8601 duration).')
param evaluationFrequency string = 'PT1M'

@description('Time window used by the query (ISO8601 duration).')
param windowSize string = 'PT5M'

@description('Whether the alert is enabled.')
param enabled bool = true

@description('Optional Action Group resource IDs to notify when alert fires.')
param actionGroupResourceIds array = []

@description('Optional custom properties passed to alert payload.')
param customProperties object = {}

@description('KQL query that detects table restore operations in AzureActivity.')
param query string = '''
AzureActivity
| where TimeGenerated >= ago(15m)
| where OperationNameValue =~ 'Microsoft.OperationalInsights/workspaces/tables/restore/action'
| where ActivityStatusValue =~ 'Success'
| project TimeGenerated, Caller, CallerIpAddress, CorrelationId, ResourceGroup, ResourceId, SubscriptionId, OperationNameValue, ActivityStatusValue
'''

resource scheduledQueryAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: alertName
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: alertName
    description: 'Triggers when a Log Analytics table restore operation succeeds.'
    enabled: enabled
    severity: severity
    scopes: [
      workspaceResourceId
    ]
    evaluationFrequency: evaluationFrequency
    windowSize: windowSize
    autoMitigate: false
    criteria: {
      allOf: [
        {
          query: query
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: actionGroupResourceIds
      customProperties: customProperties
    }
  }
}

output alertResourceId string = scheduledQueryAlert.id
