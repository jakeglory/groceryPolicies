[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $filepath = "..\definitions\lib\policy_set_definitions" #"..\assignments\lib\policy_assignments"
)

$allJSONs = Get-ChildItem $filepath -Filter "*.json"
$allJSONsWithoutParameters = Get-ChildItem $allJSONs -Exclude "*.parameters.json" 
$allJSONsWithoutParameters 

foreach ($json in $allJSONsWithoutParameters) {
    Write-Verbose "Sorting $json" -Verbose
    $jsonContent = Get-Content $json.FullName -Raw | ConvertFrom-Json
    $sortedJSON = New-Object PSCustomObject


    ## add root
    $sortedRoot = [ordered] @{}
    Get-Member -Type  NoteProperty -InputObject $jsonContent | Sort-Object Name |
      % { $sortedRoot[$_.Name] = $jsonContent.$($_.Name) }    
    Add-Member -InputObject $sortedJSON -NotePropertyMembers $sortedRoot
    
    ## add properties
    $sortedProps = [ordered] @{}
    Get-Member -Type  NoteProperty -InputObject $jsonContent.properties | Sort-Object Name |
      % { $sortedProps[$_.Name] = $jsonContent.properties.$($_.Name) }
    $sortedJSON.properties = $sortedProps
    
    ## add parameters
    $sortedPropsParameters = [ordered] @{}
    Get-Member -Type  NoteProperty -InputObject $jsonContent.properties.parameters | Sort-Object Name |
      % { $sortedPropsParameters[$_.Name] = $jsonContent.properties.parameters.$($_.Name) }
    $sortedJSON.properties.parameters = $sortedPropsParameters 
    
    ## add policyDefinitions (ONLY FOR POLICY SETS)
    $policyDefinitions = $jsonContent.properties.policyDefinitions | Sort-Object -Property policyDefinitionReferenceId
    $sortedJSON.properties.policyDefinitions = $policyDefinitions


    $sortedJSON | ConvertTo-Json -Depth 100 | Out-File $json.FullName -Encoding UTF8
}

