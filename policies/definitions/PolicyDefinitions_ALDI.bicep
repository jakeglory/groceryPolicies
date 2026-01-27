targetScope = 'managementGroup'

@allowed([
	'build'
	'dev'
	'prd'
])
param stage string = 'dev'

var stageSettings = {
	build: {
		parTargetManagementGroupId: 'build-mg-aldi'
	}
	dev: {
		parTargetManagementGroupId: 'dev-mg-aldi'
	}
	prd: {
		parTargetManagementGroupId: 'mg-aldi'
	}
}

@description('The management group scope to which the policy definitions are to be created at.')
var parTargetManagementGroupId = stageSettings[stage].parTargetManagementGroupId
var targetManagementGroupResourceId = tenantResourceId('Microsoft.Management/managementGroups', parTargetManagementGroupId)

resource pDNSconfigPolicy 'Microsoft.Authorization/policyDefinitions@2021-06-01' existing = {
	name: 'Deploy-privateDnsZoneConfigs'
	scope: managementGroup(parTargetManagementGroupId)
}
var privateDNSConfigPolicyDefinitionID = pDNSconfigPolicy.id

// This variable contains a number of objects that load in the custom Azure Policy Defintions that are provided as part of the ESLZ/ALZ reference implementation - this is automatically created in the file 'infra-as-code\bicep\modules\policy\lib\policy_definitions\_policyDefinitionsBicepInput.txt' via a GitHub action, that runs on a daily schedule, and is then manually copied into this variable. 

// all Policy Definitions have to be defined here
var customPolicyDefinitionsArray = [
	{
		name: 'AddOrReplace-Storage-BlobServicesSoftDelete'
		libDefinition: json(loadTextContent('lib/policy_definitions/AddOrReplace-Storage-BlobServicesSoftDelete.json'))
	}
	{
		name: 'AddOrReplace-Storage-ContainerSoftDelete'
		libDefinition: json(loadTextContent('lib/policy_definitions/AddOrReplace-Storage-ContainerSoftDelete.json'))
	}
	{
		name: 'Deploy-privateDnsZoneConfigs'
		libDefinition: json(loadTextContent('lib/policy_definitions/Deploy-PrivateDNSConfig.json'))
	}
	{
		name: 'Append-AppService-httpsonly'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_append_appservice_httpsonly.json'))
	}
	{
		name: 'Append-AppService-latestTLS'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_append_appservice_latesttls.json'))
	}
	{
		name: 'Append-KV-SoftDelete'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_append_kv_softdelete.json'))
	}
	{
		name: 'Append-Redis-disableNonSslPort'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_append_redis_disablenonsslport.json'))
	}
	{
		name: 'Append-Redis-sslEnforcement'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_append_redis_sslenforcement.json'))
	}
	{
		name: 'Audit-MachineLearning-PrivateEndpointId'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_audit_machinelearning_privateendpointid.json'))
	}
	{
		name: 'Deny-AA-child-resources'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_aa_child_resources.json'))
	}
	{
		name: 'Deny-AppGW-Without-WAF'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_appgw_without_waf.json'))
	}
	{
		name: 'Deny-AppServiceApiApp-http'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_appserviceapiapp_http.json'))
	}
	{
		name: 'Deny-AppServiceFunctionApp-http'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_appservicefunctionapp_http.json'))
	}
	{
		name: 'Deny-AppServiceWebApp-http'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_appservicewebapp_http.json'))
	}
	{
		name: 'Deny-Databricks-NoPublicIp'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_databricks_nopublicip.json'))
	}
	{
		name: 'Deny-Databricks-Sku'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_databricks_sku.json'))
	}
	{
		name: 'Deny-Databricks-VirtualNetwork'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_databricks_virtualnetwork.json'))
	}
	{
		name: 'Deny-MachineLearning-Aks'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_aks.json'))
	}
	{
		name: 'Deny-MachineLearning-Compute-SubnetId'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_compute_subnetid.json'))
	}
	{
		name: 'Deny-MachineLearning-Compute-VmSize'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_compute_vmsize.json'))
	}
	{
		name: 'Deny-MachineLearning-ComputeCluster-RemoteLoginPortPublicAccess'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_computecluster_remoteloginportpublicaccess.json'))
	}
	{
		name: 'Deny-MachineLearning-ComputeCluster-Scale'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_computecluster_scale.json'))
	}
	{
		name: 'Deny-MachineLearning-HbiWorkspace'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_hbiworkspace.json'))
	}
	{
		name: 'Deny-MachineLearning-PublicAccessWhenBehindVnet'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_publicaccesswhenbehindvnet.json'))
	}
	{
		name: 'Deny-MachineLearning-PublicNetworkAccess'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_machinelearning_publicnetworkaccess.json'))
	}
	{
		name: 'Deny-MySql-http'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_mysql_http.json'))
	}
	{
		name: 'Deny-PostgreSql-http'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_postgresql_http.json'))
	}
	{
		name: 'Deny-Private-DNS-Zones'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_private_dns_zones.json'))
	}
	{
		name: 'Deny-PublicEndpoint-MariaDB'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_publicendpoint_mariadb.json'))
	}
	{
		name: 'Deny-PublicIP'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_publicip.json'))
	}
	{
		name: 'Deny-RDP-From-Internet'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_rdp_from_internet.json'))
	}
	{
		name: 'Deny-Redis-http'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_redis_http.json'))
	}
	{
		name: 'Deny-Sql-minTLS'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_sql_mintls.json'))
	}
	{
		name: 'Deny-SqlMi-minTLS'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_sqlmi_mintls.json'))
	}
	{
		name: 'Deny-Storage-minTLS'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_storage_mintls.json'))
	}
	{
		name: 'Deny-Subnet-Without-Nsg'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_subnet_without_nsg.json'))
	}
	{
		name: 'Deny-Subnet-Without-Udr'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_subnet_without_udr.json'))
	}
	{
		name: 'Deny-VNET-Peer-Cross-Sub'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_vnet_peer_cross_sub.json'))
	}
	{
		name: 'Deny-VNET-Peering-To-Non-Approved-VNETs'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_vnet_peering_to_non_approved_vnets.json'))
	}
	{
		name: 'Deny-VNet-Peering'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_vnet_peering.json'))
	}
	{
		name: 'Deploy-ASC-SecurityContacts'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_asc_securitycontacts.json'))
	}
	{
		name: 'Deploy-Budget'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_budget.json'))
	}
	{
		name: 'Deploy-Custom-Route-Table'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_custom_route_table.json'))
	}
	{
		name: 'Deploy-DDoSProtection'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_ddosprotection.json'))
	}
	{
		name: 'Deploy-Diagnostics-AA'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_aa.json'))
	}
	{
		name: 'Deploy-Diagnostics-ACI'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_aci.json'))
	}
	{
		name: 'Deploy-Diagnostics-ACR'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_acr.json'))
	}
	{
		name: 'Deploy-Diagnostics-AnalysisService'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_analysisservice.json'))
	}
	{
		name: 'Deploy-Diagnostics-ApiForFHIR'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_apiforfhir.json'))
	}
	{
		name: 'Deploy-Diagnostics-APIMgmt'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_apimgmt.json'))
	}
	{
		name: 'Deploy-Diagnostics-ApplicationGateway'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_applicationgateway.json'))
	}
	{
		name: 'Deploy-Diagnostics-AVDScalingPlans'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_avdscalingplans.json'))
	}
	{
		name: 'Deploy-Diagnostics-Bastion'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_bastion.json'))
	}
	{
		name: 'Deploy-Diagnostics-CDNEndpoints'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_cdnendpoints.json'))
	}
	{
		name: 'Deploy-Diagnostics-CognitiveServices'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_cognitiveservices.json'))
	}
	{
		name: 'Deploy-Diagnostics-CosmosDB'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_cosmosdb.json'))
	}
	{
		name: 'Deploy-Diagnostics-Databricks'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_databricks.json'))
	}
	{
		name: 'Deploy-Diagnostics-DataExplorerCluster'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_dataexplorercluster.json'))
	}
	{
		name: 'Deploy-Diagnostics-DataFactory'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_datafactory.json'))
	}
	{
		name: 'Deploy-Diagnostics-DLAnalytics'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_dlanalytics.json'))
	}
	{
		name: 'Deploy-Diagnostics-EventGridSub'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_eventgridsub.json'))
	}
	{
		name: 'Deploy-Diagnostics-EventGridSystemTopic'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_eventgridsystemtopic.json'))
	}
	{
		name: 'Deploy-Diagnostics-EventGridTopic'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_eventgridtopic.json'))
	}
	{
		name: 'Deploy-Diagnostics-ExpressRoute'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_expressroute.json'))
	}
	{
		name: 'Deploy-Diagnostics-Firewall'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_firewall.json'))
	}
	{
		name: 'Deploy-Diagnostics-FrontDoor'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_frontdoor.json'))
	}
	{
		name: 'Deploy-Diagnostics-Function'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_function.json'))
	}
	{
		name: 'Deploy-Diagnostics-HDInsight'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_hdinsight.json'))
	}
	{
		name: 'Deploy-Diagnostics-iotHub'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_iothub.json'))
	}
	{
		name: 'Deploy-Diagnostics-LoadBalancer'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_loadbalancer.json'))
	}
	{
		name: 'Deploy-Diagnostics-LogicAppsISE'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_logicappsise.json'))
	}
	{
		name: 'Deploy-Diagnostics-MariaDB'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_mariadb.json'))
	}
	{
		name: 'Deploy-Diagnostics-MediaService'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_mediaservice.json'))
	}
	{
		name: 'Deploy-Diagnostics-MlWorkspace'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_mlworkspace.json'))
	}
	{
		name: 'Deploy-Diagnostics-MySQL'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_mysql.json'))
	}
	{
		name: 'Deploy-Diagnostics-NetworkSecurityGroups'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_networksecuritygroups.json'))
	}
	{
		name: 'Deploy-Diagnostics-NIC'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_nic.json'))
	}
	{
		name: 'Deploy-Diagnostics-PostgreSQL'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_postgresql.json'))
	}
	{
		name: 'Deploy-Diagnostics-PowerBIEmbedded'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_powerbiembedded.json'))
	}
	{
		name: 'Deploy-Diagnostics-RedisCache'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_rediscache.json'))
	}
	{
		name: 'Deploy-Diagnostics-Relay'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_relay.json'))
	}
	{
		name: 'Deploy-Diagnostics-SignalR'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_signalr.json'))
	}
	{
		name: 'Deploy-Diagnostics-SQLElasticPools'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_sqlelasticpools.json'))
	}
	{
		name: 'Deploy-Diagnostics-SQLMI'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_sqlmi.json'))
	}
	{
		name: 'Deploy-Diagnostics-TimeSeriesInsights'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_timeseriesinsights.json'))
	}
	{
		name: 'Deploy-Diagnostics-TrafficManager'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_trafficmanager.json'))
	}
	{
		name: 'Deploy-Diagnostics-VirtualNetwork'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_virtualnetwork.json'))
	}
	{
		name: 'Deploy-Diagnostics-VM'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_vm.json'))
	}
	{
		name: 'Deploy-Diagnostics-VMSS'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_vmss.json'))
	}
	{
		name: 'Deploy-Diagnostics-VNetGW'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_vnetgw.json'))
	}
	{
		name: 'Deploy-Diagnostics-WebServerFarm'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_webserverfarm.json'))
	}
	{
		name: 'Deploy-Diagnostics-Website'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_website.json'))
	}
	{
		name: 'Deploy-Diagnostics-WVDAppGroup'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_wvdappgroup.json'))
	}
	{
		name: 'Deploy-Diagnostics-WVDHostPools'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_wvdhostpools.json'))
	}
	{
		name: 'Deploy-Diagnostics-WVDWorkspace'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_diagnostics_wvdworkspace.json'))
	}
	{
		name: 'Deploy-FirewallPolicy'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_firewallpolicy.json'))
	}
	{
		name: 'Deploy-MySQL-sslEnforcement'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_mysql_sslenforcement.json'))
	}
	{
		name: 'Deploy-Nsg-FlowLogs-to-LA'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_nsg_flowlogs_to_la.json'))
	}
	{
		name: 'Deploy-Nsg-FlowLogs'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_nsg_flowlogs.json'))
	}
	{
		name: 'Deploy-PostgreSQL-sslEnforcement'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_postgresql_sslenforcement.json'))
	}
	{
		name: 'Deploy-Sql-AuditingSettings'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_sql_auditingsettings.json'))
	}
	{
		name: 'Deploy-SQL-minTLS'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_sql_mintls.json'))
	}
	{
		name: 'Deploy-Sql-SecurityAlertPolicies'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_sql_securityalertpolicies.json'))
	}
	{
		name: 'Deploy-Sql-vulnerabilityAssessments'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_sql_vulnerabilityassessments.json'))
	}
	{
		name: 'Deploy-SqlMi-minTLS'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_sqlmi_mintls.json'))
	}
	{
		name: 'Deploy-Storage-sslEnforcement'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_storage_sslenforcement.json'))
	}
	{
		name: 'Deploy-VNET-HubSpoke'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_vnet_hubspoke.json'))
	}
	{
		name: 'Deploy-Windows-DomainJoin'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deploy_windows_domainjoin.json'))
	}
	{
		name: 'Config-PrivateDNSopenAI'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_configure_private_dns_openAI.json'))
	}
	{
		name: '"Config-flexibleServerPrivateDNS"'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_configure_flexibleServerPrivateDNS.json'))
	}
	{
		name: 'Deny-Resource-Removal'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_deny_resource_removal.json'))
	}
	{
		name: 'Deny-Public-DNS-Zones'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_es_deny_public_dns_zones.json'))
	}
	{
		name: 'Config-Win-Sec-DCR'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_configure_windows_security_dcr.json'))
	}
	{
		name: 'Config-Linux-Sec-DCR'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_configure_linux_security_dcr.json'))
	}
	{
		name: 'sub-activity-logs-export'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_configure_sub_activity_logs_export.json'))
	}
	{
		name: 'Inherit-from-Sub'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_modify_inherit_from_sub_to_rg.json'))
	}
	{
		name: 'JustInherit-from-Sub'
		libDefinition: json(loadTextContent('lib/policy_definitions/policy_definition_inherit_from_sub_to_rg.json'))
	}
]

// all Policy Set Definitions have to be defined here
var customPolicySetDefinitionsArray = [
	{
		name: 'Allowed-Locations'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Allowed-Locations.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Allowed locations'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
				definitionParameters: policySetDefinitionAllowedLocationsParameters['Allowed locations'].parameters
			}
			{
				definitionReferenceId: 'Allowed locations for resource groups'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/e765b5de-1225-4ba3-bd56-1ac6695af988'
				definitionParameters: policySetDefinitionAllowedLocationsParameters['Allowed locations for resource groups'].parameters
			}
			{
				definitionReferenceId: 'Audit resource location matches resource group location'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/0a914e76-4921-4c19-b460-a2d36003525a'
				definitionParameters: policySetDefinitionAllowedLocationsParameters['Audit resource location matches resource group location'].parameters
			}
		]
	}
	{
		name: 'Audit-AzureBackup'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Audit-AzureBackup.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Azure Backup should be enabled for Virtual Machines'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/013e242c-8828-4970-87b3-ab247555486d'
				definitionParameters: policySetDefinitionAuditAzureBackupParameters['Azure Backup should be enabled for Virtual Machines'].parameters
			}
		]
	}
	{
		name: 'Audit-AzureEventHubSettings'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Audit-AzureEventHubSettings.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Authorization rules on the Event Hub instance should be defined'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/f4826e5f-6a27-407c-ae3e-9582eb39891d'
				definitionParameters: policySetDefinitionAuditAzureEventHubSettingsParameters['Authorization rules on the Event Hub instance should be defined'].parameters
			}
		]
	}
	{
		name: 'Audit-AzureSecuritySettings'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Audit-AzureSecuritySettings.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Cloud Services (extended support) role instances should have an endpoint protection solution installed'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1e378679-f122-4a96-a739-a7729c46e1aa'
				definitionParameters: policySetDefinitionAuditAzureSecuritySettingsParameters['Cloud Services (extended support) role instances should have an endpoint protection solution installed'].parameters
			}
			{
				definitionReferenceId: 'Microsoft Antimalware for Azure should be configured to automatically update protection signatures'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/c43e4a30-77cb-48ab-a4dd-93f175c63b57'
				definitionParameters: policySetDefinitionAuditAzureSecuritySettingsParameters['Microsoft Antimalware for Azure should be configured to automatically update protection signatures'].parameters
			}
			{
				definitionReferenceId: 'Microsoft IaaSAntimalware extension should be deployed on Windows servers'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/9b597639-28e4-48eb-b506-56b05d366257'
				definitionParameters: policySetDefinitionAuditAzureSecuritySettingsParameters['Microsoft IaaSAntimalware extension should be deployed on Windows servers'].parameters
			}
		]
	}
	{
		name: 'Audit-ComputeSettings'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Audit-ComputeSettings.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Audit virtual machines without disaster recovery configured'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/0015ea4d-51ff-4ce3-8d8c-f3f8f0179a56'
				definitionParameters: policySetDefinitionAuditComputeSettingsParameters['Audit virtual machines without disaster recovery configured'].parameters
			}
			{
				definitionReferenceId: 'Audit VMs that do not use managed disks'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/06a78e20-9358-41c9-923c-fb736d382a4d'
				definitionParameters: policySetDefinitionAuditComputeSettingsParameters['Audit VMs that do not use managed disks'].parameters
			}
		]
	}
	{
		name: 'Audit-KeyVaultSecuritySettings'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Audit-KeyVaultSecuritySettings.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Key Vault keys should have an expiration date'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0'
				definitionParameters: policySetDefinitionAuditKeyVaultSecuritySettingsParameters['Key Vault keys should have an expiration date'].parameters
			}
			{
				definitionReferenceId: 'Key Vault secrets should have an expiration date'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/98728c90-32c7-4049-8429-847dc0f4fe37'
				definitionParameters: policySetDefinitionAuditKeyVaultSecuritySettingsParameters['Key Vault secrets should have an expiration date'].parameters
			}
			{
				definitionReferenceId: 'Keys should have more than the specified number of days before expiration'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/5ff38825-c5d8-47c5-b70e-069a21955146'
				definitionParameters: policySetDefinitionAuditKeyVaultSecuritySettingsParameters['Keys should have more than the specified number of days before expiration'].parameters
			}
			{
				definitionReferenceId: 'Keys should not be active for longer than the specified number of days'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/c26e4b24-cf98-4c67-b48b-5a25c4c69eb9'
				definitionParameters: policySetDefinitionAuditKeyVaultSecuritySettingsParameters['Keys should not be active for longer than the specified number of days'].parameters
			}
			{
				definitionReferenceId: 'Secrets should have more than the specified number of days before expiration'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b0eb591a-5e70-4534-a8bf-04b9c489584a'
				definitionParameters: policySetDefinitionAuditKeyVaultSecuritySettingsParameters['Secrets should have more than the specified number of days before expiration'].parameters
			}
			{
				definitionReferenceId: 'Secrets should have the specified maximum validity period'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/342e8053-e12e-4c44-be01-c3c2f318400f'
				definitionParameters: policySetDefinitionAuditKeyVaultSecuritySettingsParameters['Secrets should have the specified maximum validity period'].parameters
			}
			{
				definitionReferenceId: 'Secrets should not be active for longer than the specified number of days'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/e8d99835-8a06-45ae-a8e0-87a91941ccfe'
				definitionParameters: policySetDefinitionAuditKeyVaultSecuritySettingsParameters['Secrets should not be active for longer than the specified number of days'].parameters
			}
		]
	}
	{
		name: 'Audit-NetworkSettings'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Audit-NetworkSettings.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'API Management services should use a virtual network'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ef619a2c-cc4d-4d03-b2ba-8c94a834d85b'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['API Management services should use a virtual network'].parameters
			}
			{
				definitionReferenceId: 'App Service apps should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/2d21331d-a4c2-4def-a9ad-ee4e1e023beb'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['App Service apps should use a virtual network service endpoint'].parameters
			}
			{
				definitionReferenceId: 'Event Hub should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d63edb4a-c612-454d-b47d-191a724fcbf0'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['Event Hub should use a virtual network service endpoint'].parameters
			}
			{
				definitionReferenceId: 'Gateway subnets should not be configured with a network security group'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/35f9c03a-cc27-418e-9c0c-539ff999d010'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['Gateway subnets should not be configured with a network security group'].parameters
			}
			{
				definitionReferenceId: 'IP firewall rules on Azure Synapse workspaces should be removed'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/56fd377d-098c-4f02-8406-81eb055902b8'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['IP firewall rules on Azure Synapse workspaces should be removed'].parameters
			}
			{
				definitionReferenceId: 'Key Vault should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ea4d6841-2173-4317-9747-ff522a45120f'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['Key Vault should use a virtual network service endpoint'].parameters
			}
			{
				definitionReferenceId: 'MariaDB server should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/dfbd9a64-6114-48de-a47d-90574dc2e489'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['MariaDB server should use a virtual network service endpoint'].parameters
			}
			{
				definitionReferenceId: 'MySQL server should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/3375856c-3824-4e0e-ae6a-79e011dd4c47'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['MySQL server should use a virtual network service endpoint'].parameters
			}
			{
				definitionReferenceId: 'Network Watcher flow logs should have traffic analytics enabled'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/2f080164-9f4d-497e-9db6-416dc9f7b48a'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['Network Watcher flow logs should have traffic analytics enabled'].parameters
			}
			{
				definitionReferenceId: 'PostgreSQL server should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/3c14b034-bcb6-4905-94e7-5b8e98a47b65'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['PostgreSQL server should use a virtual network service endpoint'].parameters
			}
			{
				definitionReferenceId: 'SQL Server should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ae5d2f14-d830-42b6-9899-df6cfe9c71a3'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['SQL Server should use a virtual network service endpoint'].parameters
			}
			{
				definitionReferenceId: 'Storage Accounts should use a virtual network service endpoint'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/60d21c4f-21a3-4d94-85f4-b924e6aeeda4'
				definitionParameters: policySetDefinitionAuditNetworkSettingsParameters['Storage Accounts should use a virtual network service endpoint'].parameters
			}
		]
	}
	{
		name: 'Audit-SQLSettings'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Audit-SQLSettings.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Azure SQL Database should be running TLS version 1.2 or newer'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/32e6bbec-16b6-44c2-be37-c5b672d103cf'
				definitionParameters: policySetDefinitionAuditSQLSettingsParameters['Azure SQL Database should be running TLS version 1.2 or newer'].parameters
			}
			{
				definitionReferenceId: 'Azure SQL Database should have Azure Active Directory Only Authentication enabled'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/abda6d70-9778-44e7-84a8-06713e6db027'
				definitionParameters: policySetDefinitionAuditSQLSettingsParameters['Azure SQL Database should have Azure Active Directory Only Authentication enabled'].parameters
			}
		]
	}
	{
		name: 'Configure-Audit-StorageAccountSettings'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Configure-Audit-StorageAccountSettings.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Enable soft-delete on blob-services'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/AddOrReplace-Storage-BlobServicesSoftDelete'
				definitionParameters: policySetDefinitionConfigureAuditStorageAccountSettingsParameters['Enable soft-delete on blob-services'].parameters
			}
			{
				definitionReferenceId: 'Enable soft-delete on containers'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/AddOrReplace-Storage-ContainerSoftDelete'
				definitionParameters: policySetDefinitionConfigureAuditStorageAccountSettingsParameters['Enable soft-delete on containers'].parameters
			}
			{
				definitionReferenceId: 'Secure transfer to storage accounts should be enabled'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9'
				definitionParameters: policySetDefinitionConfigureAuditStorageAccountSettingsParameters['Secure transfer to storage accounts should be enabled'].parameters
			}
			{
				definitionReferenceId: 'Storage account keys should not be expired'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/044985bb-afe1-42cd-8a36-9d5d42424537'
				definitionParameters: policySetDefinitionConfigureAuditStorageAccountSettingsParameters['Storage account keys should not be expired'].parameters
			}
			{
				definitionReferenceId: 'Storage accounts should be migrated to new Azure Resource Manager resources'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/37e0d2fe-28a5-43d6-a273-67d37d1f5606'
				definitionParameters: policySetDefinitionConfigureAuditStorageAccountSettingsParameters['Storage accounts should be migrated to new Azure Resource Manager resources'].parameters
			}
			{
				definitionReferenceId: 'Storage accounts should have infrastructure encryption'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/4733ea7b-a883-42fe-8cac-97454c2a9e4a'
				definitionParameters: policySetDefinitionConfigureAuditStorageAccountSettingsParameters['Storage accounts should have infrastructure encryption'].parameters
			}
			{
				definitionReferenceId: 'Storage accounts should prevent shared key access'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54'
				definitionParameters: policySetDefinitionConfigureAuditStorageAccountSettingsParameters['Storage accounts should prevent shared key access'].parameters
			}
		]
	}
	{
		name: 'Deny-AA-child-res'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny_child-AA.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Deny-AA-child-resources'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-AA-child-resources'
				definitionParameters: policySetDefinitionDenyChildAAParameters['Deny-AA-child-resources'].parameters
			}
		]
	}
	{
		name: 'Deny-PrivateDNS'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny-PrivateDNS.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Deny-Private-DNS-Zones'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Private-DNS-Zones'
				definitionParameters: policySetDefinitionDenyPrivateDNSParameters['Deny-Private-DNS-Zones'].parameters
			}
			{
				definitionReferenceId: 'Deny-PublicIP'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-PublicIP'
				definitionParameters: policySetDefinitionDenyPrivateDNSParameters['Deny-PublicIP'].parameters
			}
		]
	}
	{
		name: 'Deny-PublicAccess'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny-PublicAccess.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Deny-RDP-From-Internet'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-RDP-From-Internet'
				definitionParameters: policySetDefinitionDenyPublicAccessParameters['Deny-RDP-From-Internet'].parameters
			}
		]
	}
	{
		name: 'Deny-PublicIPs'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny-PublicIPs.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Network interfaces should disable IP forwarding'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/88c0b9da-ce96-4b03-9635-f29a937e2900'
				definitionParameters: policySetDefinitionDenyPublicIPsParameters['Network interfaces should disable IP forwarding'].parameters
			}
			{
				definitionReferenceId: 'Network interfaces should not have public IPs'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/83a86a26-fd1f-447c-b59d-e51f44264114'
				definitionParameters: policySetDefinitionDenyPublicIPsParameters['Network interfaces should not have public IPs'].parameters
			}
		]
	}
	{
		name: 'Deny-VNETPeerSandboxes'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny-VNETPeerSandboxes.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Deny vNet peering'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-vNet-peering'
				definitionParameters: policySetDefinitionDenyVNETPeerSandboxesParameters['Deny vNet peering'].parameters
			}
			{
				definitionReferenceId: 'Deny vNet peering Cross'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-VNET-Peer-Cross-Sub'
				definitionParameters: policySetDefinitionDenyVNETPeerSandboxesParameters['Deny vNet peering Cross'].parameters
			}
		]
	}
	{
		name: 'Deploy-Budget'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deploy-Budget.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Deploy a default budget on all subscriptions under the assigned scope'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-Budget'
				definitionParameters: policySetDefinitionDeployBudgetSBXSubParameters['Deploy a default budget on all subscriptions under the assigned scope'].parameters
			}
		]
	}
	{
		name: 'Deploy-privateDnsZoneConfigsNew'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deploy-privateDnsZoneConfigsNew.json'))
		libSetChildDefinitions: [
				{
						definitionReferenceId: 'Configure Azure Machine Learning workspace to use private DNS zones'
						definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ee40564d-486e-4f68-a5ca-7a621edae0fb'
						definitionParameters: policySetDefinitionDeployprivateDnsZoneConfigsNewParameters['Configure Azure Machine Learning workspace to use private DNS zones'].parameters
				}
		]
	}
	{
		name: 'Deploy-privateDnsZoneConfigs'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deploy-privateDnsZoneConfigs.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Link afs to privatelink.afs.azure.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link afs to privatelink.afs.azure.net'].parameters
			}
			{
				definitionReferenceId: 'Link App Configuration to privatelink.azconfig.io'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link App Configuration to privatelink.azconfig.io'].parameters
			}
			{
				definitionReferenceId: 'Link Automation DSCAndHybridWorker to privatelink.azure-automation.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Automation DSCAndHybridWorker to privatelink.azure-automation.net'].parameters
			}
			{
				definitionReferenceId: 'Link Automation Webook to privatelink.azure-automation.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Automation Webook to privatelink.azure-automation.net'].parameters
			}
			{
				definitionReferenceId: 'Link blob to privatelink.blob.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link blob to privatelink.blob.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link blob_secondary to privatelink.blob.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link blob_secondary to privatelink.blob.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link Cassandra to privatelink.cassandra.cosmos.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Cassandra to privatelink.cassandra.cosmos.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link Data Factory to privatelink.datafactory.azure.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Data Factory to privatelink.datafactory.azure.net'].parameters
			}
			{
				definitionReferenceId: 'Link Data Lake File System Gen2 secondary to privatelink.dfs.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Data Lake File System Gen2 secondary to privatelink.dfs.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link Data Lake File System Gen2 to privatelink.dfs.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Data Lake File System Gen2 to privatelink.dfs.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link Digital Twins to privatelink.digitaltwins.azure.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Digital Twins to privatelink.digitaltwins.azure.net'].parameters
			}
			{
				definitionReferenceId: 'Link Event Grid domain to privatelink.eventgrid.azure.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Event Grid domain to privatelink.eventgrid.azure.net'].parameters
			}
			{
				definitionReferenceId: 'Link Event Grid topic to privatelink.eventgrid.azure.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Event Grid topic to privatelink.eventgrid.azure.net'].parameters
			}
			{
				definitionReferenceId: 'Link eventHub to privatelink.servicebus.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link eventHub to privatelink.servicebus.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link file to privatelink.file.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link file to privatelink.file.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link file_secondary to privatelink.file.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link file_secondary to privatelink.file.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link Gremlin to privatelink.gremlin.cosmos.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Gremlin to privatelink.gremlin.cosmos.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link iotHub to privatelink.azure-devices.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link iotHub to privatelink.azure-devices.net'].parameters
			}
			{
				definitionReferenceId: 'Link mariadbServer to privatelink.mariadb.database.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link mariadbServer to privatelink.mariadb.database.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link MongoDB to privatelink.mongo.cosmos.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link MongoDB to privatelink.mongo.cosmos.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link mysqlServer to privatelink.mysql.database.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link mysqlServer to privatelink.mysql.database.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link postgresqlServer to privatelink.postgres.database.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link postgresqlServer to privatelink.postgres.database.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link queue to privatelink.queue.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link queue to privatelink.queue.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link queue_secondary to privatelink.queue.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link queue_secondary to privatelink.queue.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link registry to privatelink.azurecr.io'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link registry to privatelink.azurecr.io'].parameters
			}
			{
				definitionReferenceId: 'Link Relay to privatelink.servicebus.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Relay to privatelink.servicebus.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link Search Service to privatelink.search.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Search Service to privatelink.search.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link serviceBus to privatelink.servicebus.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link serviceBus to privatelink.servicebus.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link sites to privatelink.azurewebsites.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link sites to privatelink.azurewebsites.net'].parameters
			}
			{
				definitionReferenceId: 'Link sites slot to privatelink.azurewebsites.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link sites slot to privatelink.azurewebsites.net'].parameters
			}
			{
				definitionReferenceId: 'Link SQL to privatelink.documents.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link SQL to privatelink.documents.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link sqlServer to privatelink.database.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link sqlServer to privatelink.database.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link Synapse Sql to privatelink.sql.azuresynapse.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Synapse Sql to privatelink.sql.azuresynapse.net'].parameters
			}
			{
				definitionReferenceId: 'Link Synapse SqlOnDemand to privatelink.sql.azuresynapse.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Synapse SqlOnDemand to privatelink.sql.azuresynapse.net'].parameters
			}
			{
				definitionReferenceId: 'Link table to privatelink.table.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link table to privatelink.table.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link table to privatelink.table.cosmos.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link table to privatelink.table.cosmos.azure.com'].parameters
			}
			{
				definitionReferenceId: 'Link table_secondary to privatelink.table.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link table_secondary to privatelink.table.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link vault to privatelink.vaultcore.azure.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link vault to privatelink.vaultcore.azure.net'].parameters
			}
			{
				definitionReferenceId: 'Link web to privatelink.web.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link web to privatelink.web.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link web_secondary to privatelink.web.core.windows.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link web_secondary to privatelink.web.core.windows.net'].parameters
			}
			{
				definitionReferenceId: 'Link browser_authentication to privatelink.azuredatabricks.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link browser_authentication to privatelink.azuredatabricks.net'].parameters
			}
			{
				definitionReferenceId: 'Link databricks_ui_api to privatelink.azuredatabricks.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link databricks_ui_api to privatelink.azuredatabricks.net'].parameters
			}
			{
				definitionReferenceId: 'Link static_app to privatelink.azurestaticapps.net'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link static_app to privatelink.azurestaticapps.net'].parameters
			}
			{
				definitionReferenceId: 'Link Postgres Cosmos DB to privatelink.postgres.cosmos.azure.com'
				definitionId: privateDNSConfigPolicyDefinitionID
				definitionParameters: policySetDefinitionDeployPrivateDnsZoneConfigsParameters['Link Postgres Cosmos DB to privatelink.postgres.cosmos.azure.com'].parameters
			}
		]
	}
	{
		name: 'Enable-DDoS-VNET'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Enable-DDoS-VNET.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Virtual networks should be protected by Azure DDoS Protection Standard'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/94de2ad3-e0c1-4caf-ad78-5d47bbc83d3d'
				definitionParameters: policySetDefinitionEnableDDoSVNETParameters['Virtual networks should be protected by Azure DDoS Protection Standard'].parameters
			}
		]
	}
	{
		name: 'Enable-UpdateManagement'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Enable-UpdateManagement.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: '[Preview]: Configure periodic checking for missing system updates on Windows azure virtual machines'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/59efceea-0c96-497e-a4a1-4eb2290dac15'
				definitionParameters: policySetDefinitionEnableUpdateManagementParameters['[Preview]: Configure periodic checking for missing system updates on Windows azure virtual machines'].parameters
			}
			{
				definitionReferenceId: '[Preview]: Configure periodic checking for missing system updates on Linux azure virtual machines'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/59efceea-0c96-497e-a4a1-4eb2290dac15'
				definitionParameters: policySetDefinitionEnableUpdateManagementParameters['[Preview]: Configure periodic checking for missing system updates on Linux azure virtual machines'].parameters
			}
			{
				definitionReferenceId: '[Preview]: Machines should be configured to periodically check for missing system updates'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/bd876905-5b84-4f73-ab2d-2e7a7c4568d9'
				definitionParameters: policySetDefinitionEnableUpdateManagementParameters['[Preview]: Machines should be configured to periodically check for missing system updates'].parameters
			}
		]
	}
	{
		name: 'Enforce-KeyVault-Security'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Enforce-KeyVault-Security.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Append-KV-SoftDelete'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Append-KV-SoftDelete'
				definitionParameters: policySetDefinitionEnforceKeyVaultSecurityParameters['Append-KV-SoftDelete'].parameters
			}
		]
	}
	{
		name: 'Enforce-PlatformTags'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Enforce-PlatformTags.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord BillingID Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord BillingID Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Owner Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Owner Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Technical Contact Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Technical Contact Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Workload Team Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Workload Team Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Business Criticality Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Business Criticality Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Data Classification Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Data Classification Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord LZ Version Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord LZ Version Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Project Short Name Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Project Short Name Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Stage Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Stage Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Solution Line Tag from Subscription to Resource Group'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Inherit-from-Sub'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Solution Line Tag from Subscription to Resource Group'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord BillingID Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord BillingID Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Owner Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Owner Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Technical Contact Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Technical Contact Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Workload Team Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Workload Team Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Business Criticality Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Business Criticality Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Data Classification Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Data Classification Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord LZ Version Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord LZ Version Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Project Short Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Project Short Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Stage Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Stage Tag from Subscription to Resource'].parameters
			}
			{
				definitionReferenceId: 'Inherit or Modify Azure Aldi Nord Solution Line Tag from Subscription to Resource'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b27a0cbd-a167-4dfa-ae64-4337be671140'
				definitionParameters: policySetDefinitionEnforcePlatformTagsParameters['Inherit or Modify Azure Aldi Nord Solution Line Tag from Subscription to Resource'].parameters
			}
		]
	}
	{
		name: 'Deny-PublicPaaSEndpoints'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_es_deny_publicpaasendpoints.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: '[Preview]: Storage account public access should be disallowed'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['[Preview]: Storage account public access should be disallowed'].parameters
			}
			{
				definitionReferenceId: 'ACRDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/0fdf0491-d080-4575-b627-ad0e843cba0f'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.ACRDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'AFSDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/21a8cd35-125e-4d13-b82d-2e19b7208bb7'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.AFSDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'AKSDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/040732e8-d947-40b8-95d6-854c95024bf8'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.AKSDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'APIManagementServiceShouldUseASKUThatSupportsVirtualNetworks'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/73ef9241-5d81-4cd4-b483-8443d1730fe5'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.APIManagementServiceShouldUseASKUThatSupportsVirtualNetworks.parameters
			}
			{
				definitionReferenceId: 'Azure Attestation providers should use private endpoints'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/7b256a2d-058b-41f8-bed9-3f870541c40a'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Azure Attestation providers should use private endpoints'].parameters
			}
			{
				definitionReferenceId: 'Azure Cache for Redis should disable public network access'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/470baccb-7e51-4549-8b1a-3e5be069f663'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Azure Cache for Redis should disable public network access'].parameters
			}
			{
				definitionReferenceId: 'Azure Cognitive Search services should disable public network access'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ee980b6d-0eca-4501-8d54-f6290fd512c3'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Azure Cognitive Search services should disable public network access'].parameters
			}
			{
				definitionReferenceId: 'Azure SignalR Service should disable public network access'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/21a9766a-82a5-4747-abb5-650b6dbba6d0'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Azure SignalR Service should disable public network access'].parameters
			}
			{
				definitionReferenceId: 'Azure Synapse workspaces should disable public network access'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/38d8df46-cf4e-4073-8e03-48c24b29de0d'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Azure Synapse workspaces should disable public network access'].parameters
			}
			{
				definitionReferenceId: 'BatchDenyPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/74c5a0ae-5e48-4738-b093-65e23a060488'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.BatchDenyPublicIP.parameters
			}
			{
				definitionReferenceId: 'Configure API Management services to disable public network access'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/7ca8c8ac-3a6e-493d-99ba-c5fa35347ff2'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Configure API Management services to disable public network access'].parameters
			}
			{
				definitionReferenceId: 'CosmosDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/797b37f7-06b8-444c-b1ad-fc62867f335a'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.CosmosDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'Deny-PublicEndpoint-MariaDB'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-PublicEndpoint-MariaDB'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Deny-PublicEndpoint-MariaDB'].parameters
			}
			{
				definitionReferenceId: 'IoT Hub device provisioning service instances should disable public network access'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d82101f3-f3ce-4fc5-8708-4c09f4009546'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['IoT Hub device provisioning service instances should disable public network access'].parameters
			}
			{
				definitionReferenceId: 'KeyVaultDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/55615ac9-af46-4a59-874e-391cc3dfb490'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.KeyVaultDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'KeyVaultDenyPaasPublicNetwork'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/405c5871-3e91-4644-8a63-58e19d68ff5b'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.KeyVaultDenyPaasPublicNetwork.parameters
			}
			{
				definitionReferenceId: 'MySQLDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d9844e8a-1437-4aeb-a32c-0c992f056095'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.MySQLDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'MySQLFlexDenyPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/c9299215-ae47-4f50-9c54-8a392f68a052'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.MySQLFlexDenyPublicIP.parameters
			}
			{
				definitionReferenceId: 'PostgreSQLDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b52376f7-9612-48a1-81cd-1ffe4b61032c'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.PostgreSQLDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'PostgreSQLFlexDenyPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/5e1de0e3-42cb-4ebc-a86d-61d0c619ca48'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.PostgreSQLFlexDenyPublicIP.parameters
			}
			{
				definitionReferenceId: 'Public network access on Azure Data Factory should be disabled'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1cf164be-6819-4a50-b8fa-4bcaa4f98fb6'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Public network access on Azure Data Factory should be disabled'].parameters
			}
			{
				definitionReferenceId: 'Public network access on Azure IoT Hub should be disabled'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/2d6830fb-07eb-48e7-8c4d-2a442b35f0fb'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters['Public network access on Azure IoT Hub should be disabled'].parameters
			}
			{
				definitionReferenceId: 'SqlServerDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1b8ca024-1d5c-4dec-8995-b1a932b41780'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.SqlServerDenyPaasPublicIP.parameters
			}
			{
				definitionReferenceId: 'StorageDenyPaasPublicIP'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/34c877ad-507e-4c82-993e-3452a6e0ad3c'
				definitionParameters: policySetDefinitionEsDenyPublicpaasendpointsParameters.StorageDenyPaasPublicIP.parameters
			}
		]
	}
	{
		name: 'Deploy-Diagnostics-LogAnalytics'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_es_deploy_diagnostics_loganalytics.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'ApplicationGatewayDeployDiagnosticLogDeployLogAnalytics'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-Diagnostics-ApplicationGateway'
				definitionParameters: policySetDefinitionEsDeployDiagnosticsLoganalyticsParameters.ApplicationGatewayDeployDiagnosticLogDeployLogAnalytics.parameters
			}
			{
				definitionReferenceId: 'ExpressRouteDeployDiagnosticLogDeployLogAnalytics'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-Diagnostics-ExpressRoute'
				definitionParameters: policySetDefinitionEsDeployDiagnosticsLoganalyticsParameters.ExpressRouteDeployDiagnosticLogDeployLogAnalytics.parameters
			}
			{
				definitionReferenceId: 'FirewallDeployDiagnosticLogDeployLogAnalytics'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-Diagnostics-Firewall'
				definitionParameters: policySetDefinitionEsDeployDiagnosticsLoganalyticsParameters.FirewallDeployDiagnosticLogDeployLogAnalytics.parameters
			}
			{
				definitionReferenceId: 'FrontDoorDeployDiagnosticSettingsToLogAnalytics'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/6201aeb7-2b5c-4671-8ab4-5d3ba4d77f3b'
				definitionParameters: policySetDefinitionEsDeployDiagnosticsLoganalyticsParameters.FrontDoorDeployDiagnosticSettingsToLogAnalytics.parameters
			}
			{
				definitionReferenceId: 'IotHubDeployDiagnosticLogDeployLogAnalytics'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-Diagnostics-iotHub'
				definitionParameters: policySetDefinitionEsDeployDiagnosticsLoganalyticsParameters.IotHubDeployDiagnosticLogDeployLogAnalytics.parameters
			}
			{
				definitionReferenceId: 'VNetGWDeployDiagnosticLogDeployLogAnalytics'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-Diagnostics-VNetGW'
				definitionParameters: policySetDefinitionEsDeployDiagnosticsLoganalyticsParameters.VNetGWDeployDiagnosticLogDeployLogAnalytics.parameters
			}
		]
	}
	{
		name: 'Deploy-MDFC-Config'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_es_deploy_mdfc_config.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'defenderForAppServices'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b40e7bcd-a1e5-47fe-b9cf-2f534d0bfb7d'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForAppServices.parameters
			}
			{
				definitionReferenceId: 'defenderForArm'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b7021b2b-08fd-4dc0-9de7-3c6ece09faf9'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForArm.parameters
			}
			{
				definitionReferenceId: 'defenderforContainers'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/c9ddb292-b203-4738-aead-18e2716e858f'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderforContainers.parameters
			}
			{
				definitionReferenceId: 'defenderForCosmosDB'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/82bf5b87-728b-4a74-ba4d-6123845cf542'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForCosmosDB.parameters
			}
			{
				definitionReferenceId: 'defenderForKeyVaults'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1f725891-01c0-420a-9059-4fa46cb770b7'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForKeyVaults.parameters
			}
			{
				definitionReferenceId: 'defenderForOssDb'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/44433aa3-7ec2-4002-93ea-65c65ff0310a'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForOssDb.parameters
			}
			{
				definitionReferenceId: 'defenderForSqlPaas'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b99b73e7-074b-4089-9395-b7236f094491'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForSqlPaas.parameters
			}
			{
				definitionReferenceId: 'defenderForSqlServerVirtualMachines'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/50ea7265-7d8c-429e-9a7d-ca1f410191c3'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForSqlServerVirtualMachines.parameters
			}
			{
				definitionReferenceId: 'defenderForStorageAccounts'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/74c30959-af11-47b3-9ed2-a26e03f427a3'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForStorageAccounts.parameters
			}
			{
				definitionReferenceId: 'defenderForVM'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/8e86a5b6-b9bd-49d1-8e21-4bb8a0862222'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderForVM.parameters
			}
			{
				definitionReferenceId: 'Deploy-ASC-SecurityContacts'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-ASC-SecurityContacts'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.securityEmailContact.parameters
			}
			{
				definitionReferenceId: 'vulnerabilityForVM'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/13ce0167-8ca6-4048-8e6b-f996402e3c1b'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.vulnerabilityForVM.parameters
			}
			{
				definitionReferenceId: 'defenderforKubernetes'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/64def556-fbad-4622-930e-72d1d5589bf5'
				definitionParameters: policySetDefinitionEsDeployMdfcConfigParameters.defenderforKubernetes.parameters
			}
		]
	}
	{
		name: 'Deploy-Private-DNS-Zones'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_es_deploy_private_dns_zones.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-ACR'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/e9585a95-5b8c-4d03-b193-dc7eb5ac4c32'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-ACR'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-App'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/7a860e27-9ca2-4fc6-822d-c2d248c300df'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-App'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-AppServices'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b318f84a-b872-429b-ac6d-a01b96814452'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-AppServices'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-Batch'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/4ec38ebc-381f-45ee-81a4-acbc4be878f8'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-Batch'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-CognitiveSearch'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/fbc14a67-53e4-4932-abcc-2049c6706009'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-CognitiveSearch'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-CognitiveServices'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/c4bc6f10-cb41-49eb-b000-d5ab82e2a091'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-CognitiveServices'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-DiskAccess'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/bc05b96c-0b36-4ca9-82f0-5c53f96ce05a'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-DiskAccess'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-EventGridDomains'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d389df0a-e0d7-4607-833c-75a6fdac2c2d'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-EventGridDomains'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-EventGridTopics'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/baf19753-7502-405f-8745-370519b20483'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-EventGridTopics'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-EventHubNamespace'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ed66d4f5-8220-45dc-ab4a-20d1749c74e6'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-EventHubNamespace'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-File-Sync'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/06695360-db88-47f6-b976-7500d4297475'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-File-Sync'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-IoT'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/aaa64d2d-2fa3-45e5-b332-0b031b9b30e8'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-IoT'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-IoTHubs'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/c99ce9c1-ced7-4c3e-aca0-10e69ce0cb02'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-IoTHubs'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-KeyVault'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ac673a9a-f77d-4846-b2d8-a57f8e1c01d4'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-KeyVault'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-MachineLearningWorkspace'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ee40564d-486e-4f68-a5ca-7a621edae0fb'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-MachineLearningWorkspace'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-RedisCache'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/e016b22b-e0eb-436d-8fd7-160c4eaed6e2'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-RedisCache'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-ServiceBusNamespace'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/f0fcf93c-c063-4071-9668-c47474bd3564'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-ServiceBusNamespace'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-SignalR'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/b0e86710-7fb7-4a6c-a064-32e9b829509e'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-SignalR'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-Site-Recovery'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/942bd215-1a66-44be-af65-6a1c0318dbe2'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-Site-Recovery'].parameters
			}
			{
				definitionReferenceId: 'DINE-Private-DNS-Azure-Web'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/0b026355-49cb-467b-8ac4-f777874e175a'
				definitionParameters: policySetDefinitionEsDeployPrivateDnsZonesParameters['DINE-Private-DNS-Azure-Web'].parameters
			}
		]
	}
	{
		name: 'Enforce-Encryption-CMK'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_es_enforce_encryption_cmk.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: '[Deprecated]: SQL servers should use customer-managed keys to encrypt data at rest'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/0d134df8-db83-46fb-ad72-fe0c9428c8dd'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['[Deprecated]: SQL servers should use customer-managed keys to encrypt data at rest'].parameters
			}
			{
				definitionReferenceId: 'Azure API for FHIR should use a customer-managed key to encrypt data at rest'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/051cba44-2429-45b9-9649-46cec11c7119'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure API for FHIR should use a customer-managed key to encrypt data at rest'].parameters
			}
			{
				definitionReferenceId: 'Azure Batch account should use customer-managed keys to encrypt data'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/99e9ccd8-3db9-4592-b0d1-14b1715a4d8a'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure Batch account should use customer-managed keys to encrypt data'].parameters
			}
			{
				definitionReferenceId: 'Azure Cosmos DB accounts should use customer-managed keys to encrypt data at rest'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1f905d99-2ab7-462c-a6b0-f709acca6c8f'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure Cosmos DB accounts should use customer-managed keys to encrypt data at rest'].parameters
			}
			{
				definitionReferenceId: 'Azure Data Box jobs should use a customer-managed key to encrypt the device unlock password'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/86efb160-8de7-451d-bc08-5d475b0aadae'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure Data Box jobs should use a customer-managed key to encrypt the device unlock password'].parameters
			}
			{
				definitionReferenceId: 'Azure Machine Learning workspaces should be encrypted with a customer-managed key'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ba769a63-b8cc-4b2d-abf6-ac33c7204be8'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure Machine Learning workspaces should be encrypted with a customer-managed key'].parameters
			}
			{
				definitionReferenceId: 'Azure Policy definition Container registries should be encrypted with a customer-managed key'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/5b9159ae-1701-4a6f-9a7a-aa9c8ddd0580'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure Policy definition Container registries should be encrypted with a customer-managed key'].parameters
			}
			{
				definitionReferenceId: 'Azure Stream Analytics jobs should use customer-managed keys to encrypt data'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/87ba29ef-1ab3-4d82-b763-87fcd4f531f7'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure Stream Analytics jobs should use customer-managed keys to encrypt data'].parameters
			}
			{
				definitionReferenceId: 'Azure Synapse workspaces should use customer-managed keys to encrypt data at rest'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/f7d52b2d-e161-4dfa-a82b-55e564167385'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Azure Synapse workspaces should use customer-managed keys to encrypt data at rest'].parameters
			}
			{
				definitionReferenceId: 'Both operating systems and data disks in Azure Kubernetes Service clusters should be encrypted by customer-managed keys'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/7d7be79c-23ba-4033-84dd-45e2a5ccdd67'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Both operating systems and data disks in Azure Kubernetes Service clusters should be encrypted by customer-managed keys'].parameters
			}
			{
				definitionReferenceId: 'Cognitive Services accounts should enable data encryption with a customer-managed key'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/67121cc7-ff39-4ab8-b7e3-95b84dab487d'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Cognitive Services accounts should enable data encryption with a customer-managed key'].parameters
			}
			{
				definitionReferenceId: 'MySQL servers should use customer-managed keys to encrypt data at rest'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/83cef61d-dbd1-4b20-a4fc-5fbc7da10833'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['MySQL servers should use customer-managed keys to encrypt data at rest'].parameters
			}
			{
				definitionReferenceId: 'PostgreSQL servers should use customer-managed keys to encrypt data at rest'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/18adea5e-f416-4d0f-8aa8-d24321e3e274'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['PostgreSQL servers should use customer-managed keys to encrypt data at rest'].parameters
			}
			{
				definitionReferenceId: 'Storage accounts should use customer-managed key for encryption'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/6fac406b-40ca-413b-bf8e-0bf964659c25'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Storage accounts should use customer-managed key for encryption'].parameters
			}
			{
				definitionReferenceId: 'Virtual machines should encrypt temp disks, caches, and data flows between Compute and Storage resources'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/0961003e-5a0a-4549-abde-af6a37f2724d'
				definitionParameters: policySetDefinitionEsEnforceEncryptionCmkParameters['Virtual machines should encrypt temp disks, caches, and data flows between Compute and Storage resources'].parameters
			}
		]
	}
	{
		name: 'Enforce-EncryptTransit'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_es_enforce_encrypttransit.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'AADMDTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/3aa87b5a-7813-4b57-8a43-42dd9df5aaa7'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AADMDTLS.parameters
			}
			{
				definitionReferenceId: 'AKSIngressHttpsOnlyEffect'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AKSIngressHttpsOnlyEffect.parameters
			}
			{
				definitionReferenceId: 'APIAppServiceHttpsEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-AppServiceApiApp-http'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.APIAppServiceHttpsEffect.parameters
			}
			{
				definitionReferenceId: 'AppServiceEnvTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/817dcf37-e83d-4999-a472-644eada2ea1e'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AppServiceEnvTLS.parameters
			}
			{
				definitionReferenceId: 'AppServiceEnvTLSOldTLSdisabled'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d6545c6b-dd9d-4265-91e6-0b451e2f1c50'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AppServiceEnvTLSOldTLSdisabled.parameters
			}
			{
				definitionReferenceId: 'AppServiceHttpEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Append-AppService-httpsonly'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AppServiceHttpEffect.parameters
			}
			{
				definitionReferenceId: 'AppServiceminTlsVersion'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Append-AppService-latestTLS'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AppServiceminTlsVersion.parameters
			}
			{
				definitionReferenceId: 'AzFrontDoorPremTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/679da822-78a7-4eff-8fff-a899454a9970'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AzFrontDoorPremTLS.parameters
			}
			{
				definitionReferenceId: 'AzFWTLSinspEnabled'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/a58ac66d-92cb-409c-94b8-8e48d7a96596'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AzFWTLSinspEnabled.parameters
			}
			{
				definitionReferenceId: 'AzSynapseTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/8b5c654c-fb07-471b-aa8f-15fea733f140'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AzSynapseTLS.parameters
			}
			{
				definitionReferenceId: 'AzSynapseWorkpaceTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/cb3738a6-82a2-4a18-b87b-15217b9deff4'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.AzSynapseWorkpaceTLS.parameters
			}
			{
				definitionReferenceId: 'DataLakeEncrypt'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/a7ff3161-0087-490a-9ad9-ad6217f4f43a'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.DataLakeEncrypt.parameters
			}
			{
				definitionReferenceId: 'FunctionAppLatestTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1f01f1c7-539c-49b5-9ef4-d4ffa37d22e0'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.FunctionAppLatestTLS.parameters
			}
			{
				definitionReferenceId: 'FunctionLatestTlsEffect'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/f9d614c5-c173-4d56-95a7-b4437057d193'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.FunctionLatestTlsEffect.parameters
			}
			{
				definitionReferenceId: 'FunctionServiceHttpsEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-AppServiceFunctionApp-http'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.FunctionServiceHttpsEffect.parameters
			}
			{
				definitionReferenceId: 'MySQLEnableSSLDeployEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-MySQL-sslEnforcement'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.MySQLEnableSSLDeployEffect.parameters
			}
			{
				definitionReferenceId: 'MySQLEnableSSLEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-MySql-http'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.MySQLEnableSSLEffect.parameters
			}
			{
				definitionReferenceId: 'PostgreSQLEnableSSLDeployEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-PostgreSQL-sslEnforcement'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.PostgreSQLEnableSSLDeployEffect.parameters
			}
			{
				definitionReferenceId: 'PostgreSQLEnableSSLEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-PostgreSql-http'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.PostgreSQLEnableSSLEffect.parameters
			}
			{
				definitionReferenceId: 'RedisDenyhttps'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Redis-http'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.RedisDenyhttps.parameters
			}
			{
				definitionReferenceId: 'RedisdisableNonSslPort'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Append-Redis-disableNonSslPort'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.RedisdisableNonSslPort.parameters
			}
			{
				definitionReferenceId: 'RedisTLSDeployEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Append-Redis-sslEnforcement'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.RedisTLSDeployEffect.parameters
			}
			{
				definitionReferenceId: 'SQLDatabaseTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/32e6bbec-16b6-44c2-be37-c5b672d103cf'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.SQLDatabaseTLS.parameters
			}
			{
				definitionReferenceId: 'SQLManagedInstanceTLSDeployEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-SqlMi-minTLS'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.SQLManagedInstanceTLSDeployEffect.parameters
			}
			{
				definitionReferenceId: 'SQLManagedInstanceTLSEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-SqlMi-minTLS'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.SQLManagedInstanceTLSEffect.parameters
			}
			{
				definitionReferenceId: 'SQLMITLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/a8793640-60f7-487c-b5c3-1d37215905c4'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.SQLMITLS.parameters
			}
			{
				definitionReferenceId: 'SQLServerTLSDeployEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-SQL-minTLS'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.SQLServerTLSDeployEffect.parameters
			}
			{
				definitionReferenceId: 'SQLServerTLSEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Sql-minTLS'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.SQLServerTLSEffect.parameters
			}
			{
				definitionReferenceId: 'StorageDeployHttpsEnabledEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deploy-Storage-sslEnforcement'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.StorageDeployHttpsEnabledEffect.parameters
			}
			{
				definitionReferenceId: 'StorageHttpsEnabledEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Storage-minTLS'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.StorageHttpsEnabledEffect.parameters
			}
			{
				definitionReferenceId: 'WebAppServiceHttpsEffect'
				definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-AppServiceWebApp-http'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.WebAppServiceHttpsEffect.parameters
			}
			{
				definitionReferenceId: 'WinServerSecureCommTLS'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/828ba269-bf7f-4082-83dd-633417bc391d'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.WinServerSecureCommTLS.parameters
			}
			{
				definitionReferenceId: 'WinWebServerSecureComm'
				definitionId: '/providers/Microsoft.Authorization/policyDefinitions/5752e6d6-1206-46d8-8ab1-ecc2f71a8112'
				definitionParameters: policySetDefinitionEsEnforceEncrypttransitParameters.WinWebServerSecureComm.parameters
			}
		]
	}
	{
		name: 'Configure-MachineLearning-Security'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Configure-MachineLearningSecurity.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Configure Azure Machine Learning Computes to disable local authentication methods'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/a6f9a2d0-cff7-4855-83ad-4cd750666512'
				definitionParameters: policySetDefinitionConfigureMachineLearningSecurityParameters['Configure Azure Machine Learning Computes to disable local authentication methods'].parameters
			}
		]
	}
	{
		name: 'Config-PrivateDNSopenAI'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Configure-PrivateDNSopenAI.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Config-PrivateDNSopenAI'
        definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Config-PrivateDNSopenAI'
				definitionParameters: policySetDefinitionConfigPrivateDNSopenAIParameters['Config-PrivateDNSopenAI'].parameters
			}
		]
	}
	{
		name: 'Config-flexibleServerPrivateDNS'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Configure_flexibleServerPrivateDNS.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Config-flexibleServerPrivateDNS'
        definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Config-flexibleServerPrivateDNS'
				definitionParameters: policySetDefinitionConfigFlexibleServerPrivateDNSParameters['Config-flexibleServerPrivateDNS'].parameters
			}
		]
	}
	{
		name: 'Deny-ResourceDeletion'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny-ResourceDeletion.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Policy to deny removal of resource'
        definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Resource-Removal'
				definitionParameters: policySetDefinitionDenyResourceDeletionParameters['Policy to deny removal of resource'].parameters
			}
		]
	}
	{
		name: 'Deny-Public-DNS-Zones'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny-PublicDNS.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Deny-Public-DNS-Zones'
        definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Public-DNS-Zones'
				definitionParameters: policySetDefinitionDenyPublicDNSParameters['Deny-Public-DNS-Zones'].parameters
			}
		]
	}
	{
		name: 'Config-SecurityDCR'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Configure-SecurityDCR.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Associate Security DCR with Windows VM'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/244efd75-0d92-453c-b9a3-7d73ca36ed52'
				definitionParameters: policySetDefinitionConfigSecurityDCRParameters['Associate Security DCR with Windows VM'].parameters
			}
			{
				definitionReferenceId: 'Associate Security DCR with Linux VM'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/2ea82cdd-f2e8-4500-af75-67a2e084ca74'
				definitionParameters: policySetDefinitionConfigSecurityDCRParameters['Associate Security DCR with Linux VM'].parameters
			}
		]
	}
	{
		name: 'Config-SecurityDCRandAMA'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Configure-SecurityDCRwithAMA.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Associate Security DCR with Windows VM'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/244efd75-0d92-453c-b9a3-7d73ca36ed52'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Associate Security DCR with Windows VM'].parameters
			}
			{
				definitionReferenceId: 'Associate Security DCR with Linux VM'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/2ea82cdd-f2e8-4500-af75-67a2e084ca74'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Associate Security DCR with Linux VM'].parameters
			}
			{
				definitionReferenceId: '[Preview]: Assign Built-In User-Assigned Managed Identity to Virtual Machines'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d367bd60-64ca-4364-98ea-276775bddd94'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['[Preview]: Assign Built-In User-Assigned Managed Identity to Virtual Machines'].parameters
			}
			{
				definitionReferenceId: 'Configure Linux virtual machines to run Azure Monitor Agent with user-assigned managed identity-based authentication'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/ae8a10e6-19d6-44a3-a02d-a2bdfc707742'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Configure Linux virtual machines to run Azure Monitor Agent with user-assigned managed identity-based authentication'].parameters
			}
			{
				definitionReferenceId: 'Configure Windows virtual machines to run Azure Monitor Agent with user-assigned managed identity-based authentication'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/637125fd-7c39-4b94-bb0a-d331faf333a9'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Configure Windows virtual machines to run Azure Monitor Agent with user-assigned managed identity-based authentication'].parameters
			}
			{
				definitionReferenceId: 'Deploy Dependency agent for Linux virtual machines with Azure Monitoring Agent settings'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d55b81e1-984f-4a96-acab-fae204e3ca7f'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Deploy Dependency agent for Linux virtual machines with Azure Monitoring Agent settings'].parameters
			}
			{
				definitionReferenceId: 'Deploy Dependency agent to be enabled on Windows virtual machines with Azure Monitoring Agent settings'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/89ca9cc7-25cd-4d53-97ba-445ca7a1f222'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Deploy Dependency agent to be enabled on Windows virtual machines with Azure Monitoring Agent settings'].parameters
			}
			{
				definitionReferenceId: 'Configure Linux Arc-enabled machines to run Azure Monitor Agent'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/845857af-0333-4c5d-bbbc-6076697da122'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Configure Linux Arc-enabled machines to run Azure Monitor Agent'].parameters
			}
			{
				definitionReferenceId: 'Configure Windows Arc-enabled machines to run Azure Monitor Agent'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/94f686d6-9a24-4e19-91f1-de937dc171a4'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Configure Windows Arc-enabled machines to run Azure Monitor Agent'].parameters
			}
			{
				definitionReferenceId: 'Configure Linux Arc Machines to be associated with a Data Collection Rule or a Data Collection Endpoint'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/d5c37ce1-5f52-4523-b949-f19bf945b73a'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Configure Linux Arc Machines to be associated with a Data Collection Rule or a Data Collection Endpoint'].parameters
			}
			{
				definitionReferenceId: 'Configure Windows Arc Machines to be associated with a Data Collection Rule or a Data Collection Endpoint'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/c24c537f-2516-4c2f-aac5-2cd26baa3d26'
				definitionParameters: policySetDefinitionConfigSecurityDCRandAMAParameters['Configure Windows Arc Machines to be associated with a Data Collection Rule or a Data Collection Endpoint'].parameters
			}
		]
	}
	{
		name: 'Deny-SpecificResourceDeployment'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Deny-SpecificResourceDeployment.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Not allowed resource types'
        definitionId: '/providers/Microsoft.Authorization/policyDefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749'
				definitionParameters: policySetDefinitionDenySpecificResourceDeploymentParameters['Not allowed resource types'].parameters
			}
		]
	}
	{
		name: 'Configure-ActivityLogExport'
		libSetDefinition: json(loadTextContent('lib/policy_set_definitions/policy_set_definition_Configure_sub_activitylog_to_loganalytics.json'))
		libSetChildDefinitions: [
			{
				definitionReferenceId: 'Deploy Diagnostic Settings for Activity Log to Log Analytics workspace'
        definitionId: '${targetManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/sub-activity-logs-export'
				definitionParameters: policySetDefinitionConfigActivityLogExportParameters['Conf-ActivLog-Export'].parameters
			}
		]
	}
]

//Policy Set/Initiative Definition Parameter Variables
var policySetDefinitionAllowedLocationsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Allowed-Locations.parameters.json')
var policySetDefinitionAuditAzureBackupParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Audit-AzureBackup.parameters.json')
var policySetDefinitionAuditAzureEventHubSettingsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Audit-AzureEventHubSettings.parameters.json')
var policySetDefinitionAuditAzureSecuritySettingsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Audit-AzureSecuritySettings.parameters.json')
var policySetDefinitionAuditComputeSettingsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Audit-ComputeSettings.parameters.json')
var policySetDefinitionAuditKeyVaultSecuritySettingsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Audit-KeyVaultSecuritySettings.parameters.json')
var policySetDefinitionAuditNetworkSettingsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Audit-NetworkSettings.parameters.json')
var policySetDefinitionAuditSQLSettingsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Audit-SQLSettings.parameters.json')
var policySetDefinitionConfigureAuditStorageAccountSettingsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Configure-Audit-StorageAccountSettings.parameters.json')
var policySetDefinitionDenyChildAAParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny_child-AA.parameters.json')
var policySetDefinitionDenyPrivateDNSParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny-PrivateDNS.parameters.json')
var policySetDefinitionDenyPublicAccessParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny-PublicAccess.parameters.json')
var policySetDefinitionDenyPublicIPsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny-PublicIPs.parameters.json')
var policySetDefinitionDenyVNETPeerSandboxesParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny-VNETPeerSandboxes.parameters.json')
var policySetDefinitionDeployBudgetSBXSubParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deploy-Budget.parameters.json')
var policySetDefinitionDeployPrivateDnsZoneConfigsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deploy-privateDnsZoneConfigs.parameters.json')
var policySetDefinitionDeployprivateDnsZoneConfigsNewParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deploy-privateDnsZoneConfigsNew.parameters.json')
var policySetDefinitionEnableDDoSVNETParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Enable-DDoS-VNET.parameters.json')
var policySetDefinitionEnableUpdateManagementParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Enable-UpdateManagement.parameters.json')
var policySetDefinitionEnforceKeyVaultSecurityParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Enforce-KeyVault-Security.parameters.json')
var policySetDefinitionEnforcePlatformTagsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Enforce-PlatformTags.parameters.json') 
var policySetDefinitionEsDenyPublicpaasendpointsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_es_deny_publicpaasendpoints.parameters.json')
var policySetDefinitionEsDeployDiagnosticsLoganalyticsParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_es_deploy_diagnostics_loganalytics.parameters.json')
var policySetDefinitionEsDeployMdfcConfigParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_es_deploy_mdfc_config.parameters.json')
var policySetDefinitionEsDeployPrivateDnsZonesParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_es_deploy_private_dns_zones.parameters.json')
var policySetDefinitionEsEnforceEncryptionCmkParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_es_enforce_encryption_cmk.parameters.json')
var policySetDefinitionEsEnforceEncrypttransitParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_es_enforce_encrypttransit.parameters.json')
var policySetDefinitionConfigureMachineLearningSecurityParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Configure-MachineLearningSecurity.parameters.json')
var policySetDefinitionConfigPrivateDNSopenAIParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Configure-PrivateDNSopenAI.parameters.json')
var policySetDefinitionConfigFlexibleServerPrivateDNSParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Configure_flexibleServerPrivateDNS.parameters.json')
var policySetDefinitionDenyResourceDeletionParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny-ResourceDeletion.parameters.json')
var policySetDefinitionDenyPublicDNSParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny-PublicDNS.parameters.json')
var policySetDefinitionConfigSecurityDCRParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Configure-SecurityDCR.parameters.json')
var policySetDefinitionDenySpecificResourceDeploymentParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Deny-SpecificResourceDeployment.parameters.json')
var policySetDefinitionConfigActivityLogExportParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Configure_sub_activitylog_to_loganalytics.parameters.json')
var policySetDefinitionConfigSecurityDCRandAMAParameters = loadJsonContent('lib/policy_set_definitions/policy_set_definition_Configure-SecurityDCRwithAMA.parameters.json')

// Deploy Policy Definitions
// we are not using the CARML modules here. Because a module will be result in a new deployment. And with that lot of policies, many deployments will be created and this will cost much more time than without.
// also the CARML modules will give us no benefit here, because we are just using the basic functionality of the resource.
resource rPolDefALZ 'Microsoft.Authorization/policyDefinitions@2021-06-01' = [for onePolicy in customPolicyDefinitionsArray: {
	name: onePolicy.libDefinition.name
	properties: {
		description: onePolicy.libDefinition.properties.description
		displayName: onePolicy.libDefinition.properties.displayName
		metadata: onePolicy.libDefinition.properties.metadata
		mode: onePolicy.libDefinition.properties.mode
		parameters: onePolicy.libDefinition.properties.parameters
		policyRule: onePolicy.libDefinition.properties.policyRule
		policyType: 'Custom'
	}
}]

// Deploy Policy Set Definitions
resource rPolSetDefALZ 'Microsoft.Authorization/policySetDefinitions@2021-06-01' = [for onePolicySet in customPolicySetDefinitionsArray: {
	name: onePolicySet.libSetDefinition.name
	dependsOn: [
		rPolDefALZ
	]
	properties: {
		description: onePolicySet.libSetDefinition.properties.description
		displayName: onePolicySet.libSetDefinition.properties.displayName
		metadata: onePolicySet.libSetDefinition.properties.metadata
		parameters: onePolicySet.libSetDefinition.properties.parameters
		policyDefinitionGroups: contains(onePolicySet.libSetDefinition.properties, 'policyDefinitionGroups') ? onePolicySet.libSetDefinition.properties.policyDefinitionGroups : []
		policyType: contains(onePolicySet.libSetDefinition.properties, 'policyType') ? onePolicySet.libSetDefinition.properties.policyType : 'Custom'
		policyDefinitions: [for policySetDef in onePolicySet.libSetChildDefinitions: {
			policyDefinitionReferenceId: policySetDef.definitionReferenceId
			policyDefinitionId: policySetDef.definitionId
			parameters: policySetDef.definitionParameters
		}]
	}

}]

output oPolDefALZ array = [for (policy, i) in customPolicyDefinitionsArray: {
	name: rPolDefALZ[i].name
	resourceId: rPolDefALZ[i].id
}]

output oPolSetdefALZ array = [for (policySet, i) in customPolicySetDefinitionsArray: {
	name: rPolSetDefALZ[i].name
	resourceId: rPolSetDefALZ[i].id
}]
