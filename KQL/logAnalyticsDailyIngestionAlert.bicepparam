using './logAnalyticsDailyIngestionAlert.bicep'

param alertName = 'la-daily-ingestion-alert-prod'

param workspaceResourceId = '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>'

param dailyIngestionThresholdGb = 600
param severity = 2
param evaluationFrequency = 'PT1H'
param windowSize = 'P1D'
param enabled = true

param actionGroupResourceIds = [
  '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.Insights/actionGroups/<action-group-name>'
]

param customProperties = {
  source: 'policy-as-code'
  alertType: 'LogAnalyticsDailyIngestion'
}
