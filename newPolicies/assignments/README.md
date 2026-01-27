# Azure Policy as Code: Tenant-Root Definitions and MG Assignments

This repo deploys Azure Policy definitions and policy set (initiative) definitions at the Tenant Root management group, and assigns policy sets at specific management groups. It uses:

- Bicep for resource templates
- JSON for policy and initiative definitions
- PowerShell helper scripts
- Azure DevOps YAML pipeline with Workload Identity service connections

## Layout

- `infra/bicep/modules/`
  - `policyDefinitionFromFile.bicep` — deploy a custom policy definition from a JSON file
  - `policySetDefinitionFromFile.bicep` — deploy a policy set (initiative) from a JSON file
  - `policyAssignmentFromFile.bicep` — assign a policy set to a management group from a JSON file, with MI and optional role assignments
- `definitions/`
  - `policyDefinitions/` — custom policy JSON definitions discovered by scripts
  - `policySetDefinitions/` — policy set (initiative) JSON definitions discovered by scripts
- `assignments/`
  - `Build/`, `Development/`, `Production/`, `Unmanaged/` — environment folders with assignment JSON files
- `scripts/`
  - `deploy-definitions.ps1` — deploy all policies and policy sets to the Tenant Root MG
  - `deploy-assignments.ps1` — deploy assignments to target MGs, filtered by service connection key
- `azure-pipelines.yml` — DevOps pipeline with one service connection for definitions and four for assignments (parameterized)

## Naming

- The resource names come directly from the `name` field in each JSON file.
- If you need versioning, incorporate it into the JSON `name` yourself (e.g., `MyPolicy-v2025_09`).
- Metadata can include your own `version` tag as needed.

## Assignment display name convention

Assignment display name is composed as:

`[${customerName}][${scopeLastSegment}][${category}] ${policySetName}`

- `customerName`: comes from the pipeline parameter.
- `scopeLastSegment`: last non-empty segment of `assignmentJson.properties.scope` with sensible defaults per module (MG: `managementGroupId`; SUB: `subscription().subscriptionId`; RG: `resourceGroup().name`).
- `category`: sourced from local policy set JSON `properties.metadata.category` only (no Azure lookups).
- `policySetName`: if the local display name is found it is used, otherwise the last segment of `policyDefinitionId`.

## Built-in policy references in initiatives

For built-ins, provide the full policyDefinitionId (e.g., `/providers/Microsoft.Authorization/policyDefinitions/<builtin-guid>`). The sample shows a placeholder you should replace with a valid built-in policy definition ID.

## Quick start

1) Configure Azure DevOps service connections using Workload Identity Federation:
- One with rights at Tenant Root MG for definitions.
- Four with rights to assign at their respective MG scopes.

2) Update or add JSON files under `definitions/...` and environment-specific assignment JSONs under `assignments/<Env>/...`.

3) Run the pipeline and set parameters:
- Tenant Root MG ID
- Versions for policies and initiatives
- Four assignment service connection names
- Four management group IDs for assignments (A-D)
- Optionally, location and assignment filtering keys

4) The pipeline stages:
- Deploy definitions to Tenant Root MG
- Deploy policy set definitions to Tenant Root MG
- Deploy assignments using four jobs, each pointing to a specific environment folder (Build/Dev/Prod/Unmanaged)

## Notes

- Role assignments for the assignment managed identity can be provided via `roleDefinitionIds` in the assignment JSON; these are granted at the assignment scope (MG/SUB/RG) depending on where the assignment is deployed.
- Ensure the service connection used for assignments has permission to create role assignments at the target MG scopes when needed (DeployIfNotExists/Modify policies).
- Replace `PLACEHOLDER-BUILTIN-POLICY-GUID` in the sample initiative with a real built-in policy definition GUID.
