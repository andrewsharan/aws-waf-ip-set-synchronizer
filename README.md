# Cross Account WAF IP Set Blacklist Automation

## Table of Contents

- [Overview](#overview)
  - [Challenge](#challenge)
  - [Solution](#solution)
- [Architecture](#architecture)
  - [Architecture Diagram](#architecture-diagram)
  - [Services Used](#services-used)
- [WAF IP Set Synchronization Workflow](#waf-ip-set-synchronization-workflow)
- [Onboarding / Offboarding an AWS Account](#onboarding--offboarding-an-aws-account)
  - [Onboarding Workflow Diagram](#onboarding-workflow-diagram)
  - [Offboarding Workflow Diagram](#offboarding-workflow-diagram)

---

## Overview

### Challenge

When a malicious IP address is identified and added to a source AWS WAF IP set, that update must be propagated consistently across every organizational AWS account to maintain a strong security posture. Managing these updates manually across multiple accounts was repetitive, time-consuming, and prone to configuration drift. Onboarding new AWS accounts into the synchronization framework also required manual effort, which introduced operational bottlenecks.

### Solution

To address these challenges, a cost-efficient, event-driven synchronization platform was built that automatically:

- Detects AWS WAF IP set changes
- Identifies only the modified entries
- Securely assumes cross-account IAM roles
- Propagates the updates across all target accounts

To simplify onboarding, a secure Python script utility was also developed that runs directly from **AWS CloudShell**. This script automates the entire account onboarding process end to end, reducing onboarding time to under 10 seconds while maintaining strong security controls.

---

## Architecture

### Architecture Diagram

![WAF IP Synchronization Workflow](./images/IP%20Synchronization%20Workflow.png)


### Services Used

| AWS Service | Role in the Solution |
|---|---|
| **AWS IAM** | Enables secure permission management and cross-account role-based access control. |
| **AWS WAF** | Stores and enforces blacklist rules using IP sets and Web ACLs to block malicious IP addresses. |
| **Amazon EventBridge** | Detects WAF IP set update events and routes them to the centralized automation workflow. |
| **AWS Lambda** | Processes events, performs validation checks, and synchronizes IP set updates across accounts. |
| **Amazon CloudWatch** | Captures Lambda and CloudShell logs, and provides monitoring and debugging capabilities. |
| **AWS Security Token Service (STS)** | Provides temporary credentials that enable secure cross-account role assumption without long-term access keys. |
| **AWS CloudTrail** | Captures WAF update events and pushes them to EventBridge. |
| **Amazon DynamoDB** | Stores the previous IP set snapshot and tracks IP addresses. |
| **Amazon S3** | Stores target account metadata for cross-account automation. |
| **AWS CloudShell** | Stores and executes the account onboarding script. |

---

## WAF IP Set Synchronization Workflow

1. Log in to the **Source AWS account** and open the **WAF & Shield** console.
2. Go to **IP sets**, select the IP set, add or remove IP addresses, and save the changes.
3. **AWS CloudTrail** captures the `UpdateIPSet` API call. **Amazon EventBridge** receives the event, matches it against the specific IP set ID, and the matching rule triggers the **Lambda** function.
4. The Lambda function validates the event, loads the target account metadata (`config.json`) from **Amazon S3**, and reads the previous IP set snapshot from **DynamoDB** to track the IPs processed during the current execution.
5. The Lambda function compares the latest IP set changes with the previous snapshot to identify added or removed IP addresses.
6. The Lambda function assumes a cross-account IAM role in each target AWS account, then retrieves and updates the target IP sets using a `LockToken` retry mechanism to handle conflicts.
7. Once the updates are complete, the Lambda function stores the latest IP set snapshot in DynamoDB and sends an **Amazon SNS** email notification with a `✅ SYNCED` status and a summary of the processed accounts.
8. If the email shows `⚠️ SKIPPED`, no changes were detected, or the target accounts already contain the IPs. The Lambda function exits early to avoid unnecessary AWS WAF API calls.
9. If the email shows `🚨 FAILED`, an error occurred during execution. Check the Lambda logs in **Amazon CloudWatch Logs** to troubleshoot, resolve the issue, and re-add the IPs.

---

## Onboarding / Offboarding an AWS Account

Use the following procedure to onboard — or offboard — an AWS account from the WAF IP Set Blacklist Automation framework.

1. Create a CloudFormation stack in the target account to provision the execution IAM role, with the required customer-managed policy attached.
2. Log in to the source AWS account and navigate to **CloudShell**.
3. From the CloudShell home directory, download the onboarding script from S3:

   ```bash
   aws s3 cp <script URI> .
   ```

4. Run the script:

   ```bash
   python waf-account-onboarding-script.py
   ```

5. Select the operation to perform — `ONBOARD` or `OFFBOARD` — and enter the password to proceed:

   ```text
   Password: *****
   ```

6. The script prompts for four input parameters:

   | Parameter | Description |
   |---|---|
   | Target Account ID | Must match exactly |
   | Target Account Name | User-defined |
   | Target Account Region | Region where WAF is deployed | Must match exactly |
   | Target WAF IP Set Name | Must match exactly |

7. Once the password is validated, the existing IAM role that you are currently assuming assumes the **Operator** role, which in turn assumes the cross-account execution role to provision the IAM role. A cross-account IAM role is automatically created in the target account, with an inline policy that grants only the permissions required to retrieve and update the specified IP set.
8. After the IAM role is provisioned, the process returns to the source account and updates the Lambda execution role policy so the Lambda function can assume the newly created role in the target account. The S3 config is also updated with the latest target account metadata.
9. Execution logs are written to CloudWatch, and an email notification is sent to the users with one of the following statuses:

   | Operation | Status | Meaning |
   |---|---|---|
   | Onboard | `✅ ONBOARDED` | Account onboarded successfully |
   | Onboard | `🚨 ONBOARD_FAILED` | Onboarding failed |
   | Offboard | `✅ OFFBOARDED` | Account offboarded successfully |
   | Offboard | `🚨 OFFBOARD_FAILED` | Offboarding failed |

> **Note:** Selecting the `OFFBOARD` operation decommissions the cross-account IAM role, removes the `sts:AssumeRole` resource block from the Lambda execution role, and deletes the corresponding S3 target account metadata entry.

--- 

### Onboarding Workflow Diagram

![AWS Account Onboarding Workflow — architecture](./images/Account%20Onboarding%20Workflow.png)


### Offboarding Workflow Diagram

![AWS Account Offboarding Workflow — architecture](./images/Account%20Offboarding%20Workflow.png)


## Outcome

This solution significantly simplifies **multi-account AWS WAF blacklist rule management** by ensuring consistent blacklist enforcement across the organization. It eliminates manual synchronization efforts, reduces operational overhead, minimizes configuration drift, and improves overall reliability.

By combining an **event-driven synchronization engine** with a fully **automated account onboarding workflow**, the team can now scale or detach WAF rule management across AWS accounts with a single command while maintaining strong governance and security controls.
