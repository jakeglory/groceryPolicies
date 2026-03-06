using './logAnalyticsAnomalyDetectionAlert.bicep'

param alertName = 'la-anomaly-detection-alert-prod'

param workspaceResourceId = '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>'

param severity = 2
param evaluationFrequency = 'PT15M'
param windowSize = 'PT1H'
param enabled = true

param actionGroupResourceIds = [
  '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.Insights/actionGroups/<action-group-name>'
]

param customProperties = {
  source: 'policy-as-code'
  alertType: 'LogAnalyticsAnomalyDetection'
}
