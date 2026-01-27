# Azure Policy Remediation Pipeline

This Azure DevOps pipeline automatically remediates non-compliant resources for up to three Azure Policy assignments (Build, Dev, Prod). It runs daily at 22:00 Berlin time and uses Azure best practices for querying and remediating policies.

---

## Features

- **Supports three environments:** Build, Dev, Prod
- **Independent stages:** Each environment runs in its own stage; stages are not dependent on each other
- **Parameter-driven:** Assignment IDs, scopes, and service connections are provided as parameters
- **Validation:** Skips remediation gracefully if required parameters are missing
- **Resource limits:** Enforces Azure remediation limits (max 50,000 resources per task)
- **Scheduled execution:** Runs every day at 22:00 Berlin time (W. Europe Standard Time)

---

## How It Works

1. **Scheduled Trigger:**  
   The pipeline runs automatically every day at the scheduled time.

2. **Parameter Validation:**  
   Each stage checks if assignment ID, scope, and service connection are provided.  
   If any are missing, the stage is skipped and marked as succeeded.

3. **Query Non-Compliant Policies:**  
   Uses Azure Resource Graph to find non-compliant resources for each assignment.

4. **Remediation:**  
   Creates remediation tasks for policies with `DeployIfNotExists` or `Modify` effects.

5. **Summary Output:**  
   Each stage outputs the number of policies processed, successful, and failed remediation tasks.

---

## Parameters

| Name                  | Description                                 | Default Value                                      |
|-----------------------|---------------------------------------------|----------------------------------------------------|
| prodAssignmentId      | Prod Policy Assignment Resource ID           | (empty)                                            |
| prodScope             | Prod Assignment Scope                        | `/providers/Microsoft.Management/managementGroups/`|
| prodServiceConnection | Prod Azure Service Connection                | `prod-connection`                                  |
| buildAssignmentId     | Build Policy Assignment Resource ID          | (empty)                                            |
| buildScope            | Build Assignment Scope                       | `/providers/Microsoft.Management/managementGroups/`|
| buildServiceConnection| Build Azure Service Connection               | `build-connection`                                 |
| devAssignmentId       | Dev Policy Assignment Resource ID            | (empty)                                            |
| devScope              | Dev Assignment Scope                         | `/providers/Microsoft.Management/managementGroups/`|
| devServiceConnection  | Dev Azure Service Connection                 | `dev-connection`                                   |
| resourceCount         | Number of resources to remediate per task    | `5000`                                             |

---

## Folder Structure

```
newPolicies/
  remediation/
    policyRemediationScheduled.yml
```

---

## Usage

1. **Configure parameters:**  
   Edit the pipeline YAML or set parameters in the Azure DevOps UI for each environment.

2. **Service connections:**  
   Ensure the specified Azure service connections exist and have permissions to remediate policies.

3. **Run the pipeline:**  
   The pipeline will run automatically on schedule. You can also trigger it manually.

4. **Monitor results:**  
   Check the pipeline logs for remediation summaries and any warnings or errors.

---

## Notes

- If you do not provide assignment ID, scope, or service connection for an environment, that stage will be skipped.
- Stages run independently and in parallel.
- Remediation tasks are created only for non-compliant policies with supported effects.

---

## Azure Best Practices

- Uses Azure Resource Graph for efficient querying.
- Enforces Azure remediation resource limits.
- Validates parameters before running remediation.
- Uses separate service connections for isolation and security.

---

## Support

For issues or questions, contact your Azure DevOps administrator or open an issue in