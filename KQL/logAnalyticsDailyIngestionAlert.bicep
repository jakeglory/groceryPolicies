targetScope = 'resourceGroup'

@description('Name of the scheduled query alert rule.')
param alertName string = 'la-daily-ingestion-alert'

@description('Azure region for the alert resource.')
param location string = resourceGroup().location

@description('Resource ID of the target Log Analytics workspace.')
param workspaceResourceId string

@description('Daily ingestion threshold in GB. Alert fires when ingestion is greater than this value.')
@minValue(1)
param dailyIngestionThresholdGb int = 600

@description('Severity of the alert from 0 (Critical) to 4 (Verbose).')
@minValue(0)
@maxValue(4)
param severity int = 2

@description('How often the query runs (ISO8601 duration).')
param evaluationFrequency string = 'PT1H'

@description('Time window used by the query (ISO8601 duration).')
param windowSize string = 'P1D'

@description('Whether the alert is enabled.')
param enabled bool = true

@description('Optional Action Group resource IDs to notify when alert fires.')
param actionGroupResourceIds array = []

@description('Optional custom properties passed to alert payload.')
param customProperties object = {}

@description('KQL query that computes billable daily ingestion. Quantity is in MB in Usage, converted to GB by dividing by 1000.')
param query string = '''
Usage
| where TimeGenerated >= ago(1d)
| where IsBillable == true
| summarize DailyIngestionGB = sum(Quantity) / 1000.0
| project DailyIngestionGB
'''

resource scheduledQueryAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: alertName
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: alertName
    description: 'Triggers when Log Analytics daily ingestion exceeds the configured threshold.'
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
          threshold: dailyIngestionThresholdGb
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
