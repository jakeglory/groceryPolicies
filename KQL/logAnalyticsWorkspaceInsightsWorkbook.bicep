targetScope = 'resourceGroup'

@description('Display name of the Azure Workbook.')
param workbookDisplayName string = 'Log Analytics - Anomalies, Metrics & Cost Savings'

@description('Location of the workbook resource.')
param location string = resourceGroup().location

@description('Resource ID of the Log Analytics workspace shown by this workbook.')
param workspaceResourceId string

@description('Optional workbook resource name (GUID). Leave empty to auto-generate.')
param workbookId string = ''

var workbookName = empty(workbookId) ? guid(workspaceResourceId, workbookDisplayName) : workbookId

var workbookData = {
  version: 'Notebook/1.0'
  items: [
    {
      type: 1
      name: 'title'
      content: '# Log Analytics Workspace Insights\nAnomalies, key metrics, and cost-saving opportunities for the selected workspace.'
    }
    {
      type: 1
      name: 'anomalies-header'
      content: '## Anomalies'
    }
    {
      type: 3
      name: 'ingestion-anomalies'
      content: {
        version: 'KqlItem/1.0'
        query: '''
let lookback = 14d;
let step = 1h;
Usage
| where TimeGenerated >= ago(lookback)
| where IsBillable == true
| summarize IngestionGB = sum(Quantity) / 1024.0 by bin(TimeGenerated, step)
| make-series IngestionGB = sum(IngestionGB) default=0 on TimeGenerated from ago(lookback) to now() step step
| extend (Anomalies, Score, Baseline) = series_decompose_anomalies(IngestionGB, 3)
| mv-expand TimeGenerated to typeof(datetime), IngestionGB to typeof(real), Anomalies to typeof(double), Score to typeof(double), Baseline to typeof(real)
| where Anomalies != 0
| project TimeGenerated, IngestionGB, BaselineGB = Baseline, Score, AnomalyType = iff(Anomalies > 0, 'Spike', 'Dip')
| top 200 by abs(Score) desc
'''
        size: 0
        title: 'Hourly ingestion anomalies (14 days)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'table'
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 3
      name: 'table-level-anomalies'
      content: {
        version: 'KqlItem/1.0'
        query: '''
let lookback = 30d;
let step = 1d;
Usage
| where TimeGenerated >= ago(lookback)
| where IsBillable == true
| summarize DailyGB = sum(Quantity) / 1024.0 by TableName = DataType, bin(TimeGenerated, step)
| make-series DailyGB = sum(DailyGB) default=0 on TimeGenerated from ago(lookback) to now() step step by TableName
| extend (Anomalies, Score, Baseline) = series_decompose_anomalies(DailyGB, 3)
| mv-expand TimeGenerated to typeof(datetime), DailyGB to typeof(real), Anomalies to typeof(double), Score to typeof(double), Baseline to typeof(real)
| where Anomalies != 0
| project TimeGenerated, TableName, DailyGB, BaselineGB = Baseline, Score, AnomalyType = iff(Anomalies > 0, 'Spike', 'Dip')
| top 250 by abs(Score) desc
'''
        size: 0
        title: 'Table-level daily anomalies (30 days)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'table'
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 3
      name: 'table-restore-events'
      content: {
        version: 'KqlItem/1.0'
        query: '''
AzureActivity
| where TimeGenerated >= ago(30d)
| where OperationNameValue =~ 'Microsoft.OperationalInsights/workspaces/tables/restore/action'
| project TimeGenerated, Caller, CallerIpAddress, CorrelationId, ResourceGroup, ResourceId, ActivityStatusValue, OperationNameValue
| order by TimeGenerated desc
'''
        size: 0
        title: 'Table restore operations (30 days)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'table'
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 1
      name: 'metrics-header'
      content: '## Core Metrics'
    }
    {
      type: 3
      name: 'daily-ingestion-trend'
      content: {
        version: 'KqlItem/1.0'
        query: '''
Usage
| where TimeGenerated >= ago(30d)
| where IsBillable == true
| summarize DailyGB = sum(Quantity) / 1024.0 by Day = bin(TimeGenerated, 1d)
| order by Day asc
'''
        size: 0
        title: 'Daily billable ingestion trend (30 days)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'timechart'
        chartSettings: {
          yAxis: [
            {
              id: 'DailyGB'
              settings: {
                axisType: 2
              }
            }
          ]
        }
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 3
      name: 'top-tables'
      content: {
        version: 'KqlItem/1.0'
        query: '''
Usage
| where TimeGenerated >= ago(30d)
| summarize BillableGB = round(sumif(Quantity, IsBillable == true) / 1024.0, 2) by TableName = DataType
| top 20 by BillableGB desc
'''
        size: 0
        title: 'Top 20 tables by billable ingestion (30 days)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'barchart'
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 3
      name: 'health-metrics'
      content: {
        version: 'KqlItem/1.0'
        query: '''
Usage
| where TimeGenerated >= ago(24h)
| summarize
    TotalBillableGB = round(sumif(Quantity, IsBillable == true) / 1024.0, 2),
    TotalNonBillableGB = round(sumif(Quantity, IsBillable == false) / 1024.0, 2),
    DistinctTables = dcount(DataType)
| extend EstimatedDailyCostUSD = round(TotalBillableGB * 2.76, 2)
'''
        size: 0
        title: 'Workspace ingestion KPIs (last 24h)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'table'
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 1
      name: 'cost-header'
      content: '## Potential Cost Savings'
    }
    {
      type: 3
      name: 'cost-drivers'
      content: {
        version: 'KqlItem/1.0'
        query: '''
Usage
| where TimeGenerated >= ago(30d)
| where IsBillable == true
| summarize BillableGB = sum(Quantity) / 1024.0 by TableName = DataType
| where BillableGB > 1
| extend EstimatedCostUSD = round(BillableGB * 2.76, 2)
| order by EstimatedCostUSD desc
'''
        size: 0
        title: 'Estimated cost drivers by table (30 days)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'table'
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 3
      name: 'growth-candidates'
      content: {
        version: 'KqlItem/1.0'
        query: '''
let recent =
    Usage
    | where TimeGenerated >= ago(7d)
    | where IsBillable == true
    | summarize Recent7dGB = sum(Quantity) / 1024.0 by TableName = DataType;
let previous =
    Usage
    | where TimeGenerated between (ago(14d) .. ago(7d))
    | where IsBillable == true
    | summarize Previous7dGB = sum(Quantity) / 1024.0 by TableName = DataType;
recent
| join kind=leftouter previous on TableName
| extend Previous7dGB = coalesce(Previous7dGB, 0.0)
| extend GrowthPct = iff(Previous7dGB == 0.0, 100.0, round(((Recent7dGB - Previous7dGB) / Previous7dGB) * 100.0, 2))
| where Recent7dGB >= 5 and GrowthPct >= 50
| extend Recommendation = 'Review data collection settings / filter noisy logs for this table'
| project TableName, Recent7dGB, Previous7dGB, GrowthPct, Recommendation
| order by GrowthPct desc
'''
        size: 0
        title: 'High-growth tables (potential optimization targets)'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'table'
        crossComponentResources: [
          workspaceResourceId
        ]
      }
    }
    {
      type: 1
      name: 'cost-guidance'
      content: '### Recommended actions\n- Tune diagnostics and data collection rules for high-growth tables.\n- Apply table-level retention tiers where allowed by compliance requirements.\n- Move infrequently used historical data to archive tier when suitable.\n- Exclude low-value verbose logs at source when possible.'
    }
  ]
  isLocked: false
  fallbackResourceIds: [
    workspaceResourceId
  ]
}

resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = {
  name: workbookName
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    category: 'workbook'
    sourceId: workspaceResourceId
    serializedData: string(workbookData)
    version: '1.0'
  }
}

output workbookResourceId string = workbook.id
