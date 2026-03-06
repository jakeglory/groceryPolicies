targetScope = 'resourceGroup'

@description('Name of the scheduled query alert rule.')
param alertName string = 'la-anomaly-detection-alert'

@description('Azure region for the alert resource.')
param location string = resourceGroup().location

@description('Resource ID of the target Log Analytics workspace.')
param workspaceResourceId string

@description('Severity of the alert from 0 (Critical) to 4 (Verbose).')
@minValue(0)
@maxValue(4)
param severity int = 2

@description('How often the query runs (ISO8601 duration).')
param evaluationFrequency string = 'PT15M'

@description('Time window used by the query (ISO8601 duration).')
param windowSize string = 'PT1H'

@description('Whether the alert is enabled.')
param enabled bool = true

@description('Optional Action Group resource IDs to notify when alert fires.')
param actionGroupResourceIds array = []

@description('Optional custom properties passed to alert payload.')
param customProperties object = {}

@description('KQL query that detects ingestion anomalies in the workspace using the Usage table.')
param query string = '''
let sensitivity = 3;
let lookback = 14d;
let bucket = 1h;
Usage
| where TimeGenerated >= ago(lookback)
| where IsBillable == true
| summarize IngestionGB = sum(Quantity) / 1000.0 by bin(TimeGenerated, bucket)
| make-series IngestionGB = sum(IngestionGB) default=0 on TimeGenerated from ago(lookback) to now() step bucket
| extend (anomalies, score, baseline) = series_decompose_anomalies(IngestionGB, sensitivity)
| extend LatestAnomaly = toint(anomalies[array_length(anomalies) - 1])
| extend LatestValueGB = todouble(IngestionGB[array_length(IngestionGB) - 1])
| extend LatestBaselineGB = todouble(baseline[array_length(baseline) - 1])
| extend LatestScore = todouble(score[array_length(score) - 1])
| where LatestAnomaly != 0
| project LatestValueGB, LatestBaselineGB, LatestScore, LatestAnomaly
'''

resource scheduledQueryAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: alertName
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: alertName
    description: 'Triggers when an ingestion anomaly is detected in Log Analytics Usage data.'
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
