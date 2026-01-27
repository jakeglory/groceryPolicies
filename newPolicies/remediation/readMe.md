# Azure Policy Assignment Remediation Pipeline

This Azure DevOps pipeline automates the remediation of non-compliant **DeployIfNotExists** and **Modify** policies for a given Azure Policy Assignment. It uses Azure PowerShell and Azure Resource Graph for efficient querying and remediation task creation.

---

## Parameters

| Name              | Description                                                                                  | Example                                                                 |
|-------------------|---------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| `assignmentId`    | The full resource ID of the policy assignment to remediate.                                 | `/providers/Microsoft.Management/managementGroups/build-mg-aldi/providers/Microsoft.Authorization/policyAssignments/enforce-platformtags` |
| `scope`           | The scope at which the assignment is applied (management group or subscription resource ID). | `/providers/Microsoft.Management/managementGroups/build-mg-aldi` |
| `serviceConnection` | Name of the Azure DevOps service connection to use for authentication.                    | `serviceconnection-AN-Azure-ControlRepo-build-mg-aldi`                                            |
| `resourceCount`   | Number of resources to remediate per task (max 50,000).                                     | `5000`                                                                  |

---

## Pipeline Flow

1. **Query Non-Compliant Policies**
    - Uses Azure Resource Graph to find all non-compliant policies with `DeployIfNotExists` or `Modify` effect for the given assignment.
    - Outputs a summary and saves the results for the next step.

2. **Create Remediation Tasks**
    - For each non-compliant policy, creates a remediation task using `Start-AzPolicyRemediation`.
    - Remediation task names are unique and include a timestamp and a counter.
    - Handles Azure API limits and provides a summary of successes and failures.

---

## How It Works

### 1. Query Non-Compliant Policies

- Uses `Search-AzGraph` to efficiently find non-compliant policies.
- Filters for `DeployIfNotExists` and `Modify` effects only.
- Results are saved for the remediation step.

### 2. Create Remediation Tasks

- Iterates through each non-compliant policy.
- Creates a remediation task with a unique name for each.
- Uses `ParallelDeploymentCount` for efficient parallel remediation.
- Handles errors and logs warnings if any remediation task fails.

---

## Usage Example

```yaml
parameters:
  - name: assignmentId
    default: '/providers/Microsoft.Management/managementGroups/build-mg-aldi/providers/Microsoft.Authorization/policyAssignments/enforce-platformtags'
  - name: scope
    default: '/providers/Microsoft.Management/managementGroups/build-mg-aldi'
  - name: serviceConnection
    default: 'serviceconnection-AN-Azure-ControlRepo-build-mg-aldi'
  - name: resourceCount
    default: 500
```

---

## Sample Scope Values

- **Management Group:**  
  `/providers/Microsoft.Management/managementGroups/build-mg-aldi`
- **Subscription:**  
  `/subscriptions/00000000-0000-0000-0000-000000000000`

---

## Notes & Best Practices

- The pipeline enforces a maximum of 50,000 resources per remediation task (Azure limit).
- Remediation task names are truncated if they exceed Azure's 64-character limit.
- All operations use Azure PowerShell for best compatibility and feature support.
- Errors and warnings are logged to the Azure DevOps pipeline for easy troubleshooting.

---

## References

- [Azure Policy Remediation Documentation](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources)
- [Start-AzPolicyRemediation Cmdlet](https://learn.microsoft.com/en-us/powershell/module/az.resources/start-azpolicyremediation)
- [Azure Resource Graph](https://learn.microsoft.com/en-us/azure/governance/resource-graph/)

---

## Troubleshooting

- Ensure the service connection has sufficient permissions for Policy and Resource Graph.
- Double-check the `assignmentId` and `scope` values for typos.
- Review pipeline logs for any warnings or errors related to remediation task creation.
