

$definitions = New-AzManagementGroupDeployment -TemplateFile "C:\git\ALDINord\AN-Azure-PlatformInfra\policies\definitions\PolicyDefinitions_ALDI.bicep" -ManagementGroupId dev-mg-aldi -Location westeurope -Verbose -WhatIf

$assignments = New-AzManagementGroupDeployment -TemplateFile "C:\git\ALDINord\AN-Azure-PlatformInfra\policies\assignments\PolicyAssignments_ALDI.bicep" -ManagementGroupId dev-mg-aldi -Location westeurope -Verbose -WhatIf



$all = New-AzManagementGroupDeployment -TemplateFile "C:\git\ALDINord\AN-Azure-PlatformInfra\policies\deploy.bicep" -ManagementGroupId dev-mg-aldi -Location westeurope -Verbose #-WhatIf
