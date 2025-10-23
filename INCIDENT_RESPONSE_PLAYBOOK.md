# Incident Response Playbook: Automated EC2 Instance Compromise

## 🚨 Classification
- **Incident Type:** Compromised EC2 Instance
- **Severity:** HIGH / CRITICAL
- **Automation Level:** Fully Automated (Zero-Touch)

## 1. Executive Summary
This playbook details the automated response to a compromised EC2 instance, triggered by high-severity AWS GuardDuty findings. The process autonomously contains the threat, preserves forensic evidence, and restores service availability, reducing Mean Time to Respond (MTTR) from hours to minutes.

## 2. Trigger Conditions
The automated response is initiated by an **AWS CloudWatch Event Rule** matching the following pattern:
- **Source:** `aws.guardduty`
- **Finding Type:** High/Critical severity EC2 compromises (e.g., `UnauthorizedAccess:EC2/`, `CryptoCurrency:EC2/`, `Backdoor:EC2/`)
- **Resource Type:** EC2 Instance

## 3. Roles & Responsibilities
| Role | Responsibilities | Contact |
| :--- | :--- | :--- |
| **Automated Lambda Function** | Executes containment & remediation | `compromised_ec2_response` |
| **Security Engineer** | Monitors alerts, validates automated actions, leads post-mortem analysis | Escalation List |
| **Cloud Operations** | Assists with forensic analysis & resource management | Escalation List |

## 4. Automated Response Procedure

### Phase 1: Detection & Validation (Automated)
1.  **Event Trigger:** GuardDuty finding is routed via EventBridge.
2.  **Payload Validation:** Lambda function parses the event and extracts the instance ID.
3.  **Source Verification:** Validates the event source is GuardDuty.

### Phase 2: Containment (Automated)
**Goal:** Immediately isolate the instance from the network and production traffic.
1.  **Traffic Drain:**
    - Deregister instance from all associated Elastic Load Balancer (ELB) Target Groups.
    - *Validation: Check ELB console for instance state 'draining'.*
2.  **AutoScaling Detachment:**
    - Detach instance from its Auto Scaling Group (without reducing desired capacity).
    - *Validation: Check ASG activity history for detachment event.*
3.  **Network Quarantine:**
    - Replace all existing Security Groups with a restrictive "quarantine" SG that denies all inbound/outbound traffic.
    - *Validation: Check EC2 console for applied Security Group.*

### Phase 3: Evidence Preservation (Automated)
**Goal:** Create a forensic snapshot for later analysis.
1.  **Snapshot Volumes:**
    - Create EBS snapshots of all volumes attached to the instance.
    - Tag snapshots with `ForensicEvidence: True` and `Retention: DoNotDelete`.
    - *Validation: Check EBS Snapshots console for new snapshots.*

### Phase 4: Eradication & Recovery (Automated)
**Goal:** Remove the compromised resource and restore service.
1.  **Instance Termination:**
    - Terminate the compromised instance.
    - *Validation: Check EC2 console for instance state 'terminated'.*
2.  **Service Restoration:**
    - The Auto Scaling Group automatically launches a new, clean instance to maintain capacity.
    - *Validation: Check ASG for new instance and ELB for healthy targets.*

## 5. Communication Plan
- **Automated Alerts:** SNS notification sent to `#security-alerts` channel/email upon containment initiation.
- **Status Updates:** Security Hub finding is updated with `WORKFLOW: RESOLVED` and `RECORD_STATE: ARCHIVED`.
- **Post-Incident:** Formal report generated after post-mortem.

## 6. Post-Incident Activity
1.  **Forensic Analysis:** Analyze preserved EBS snapshots to determine root cause and Indicators Of Compromise (IOCs).
2.  **Playbook Review:** Conduct a blameless post-mortem. Update this playbook based on lessons learned.
3.  **Compliance Reporting:** Document the incident for relevant audits (PCI-DSS, HIPAA).

## 7. Appendix
- **Lambda Function ARN:** `arn:aws:lambda:us-east-1:...:function:compromised_ec2_response`
- **Quarantine Security Group:** `compromise-response-quarantine-sg`

