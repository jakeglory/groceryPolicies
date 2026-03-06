using './logAnalyticsTableRestoreAlert.bicep'

param alertName = 'la-table-restore-alert-prod'

param workspaceResourceId = '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>'

param severity = 2
param evaluationFrequency = 'PT1M'
param windowSize = 'PT5M'
param enabled = true

param actionGroupResourceIds = [
  '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.Insights/actionGroups/<action-group-name>'
]

param customProperties = {
  source: 'policy-as-code'
  alertType: 'LogAnalyticsTableRestore'
}
