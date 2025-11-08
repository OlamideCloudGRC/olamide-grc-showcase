# Architecture Overview

## High-Level Design
[[GRC Architecture](./architecture.svg)]

## Architecture Components

### 1. Governance & Policy Layer
- **AWS Organizations SCPs** - Prevent dangerous actions
- **AWS Config** - Continuous compliance monitoring
- **Resource Tagging Enforcement** - Mandatory project tagging

### 2. Security & Compliance Layer  
- **AWS GuardDuty** - Threat detection for EC2, S3, IAM
- **AWS Security Hub** - Centralized security findings
- **Compliance Mapping** - NIST, CIS, PCI-DSS controls

### 3. Automation & Response Layer
- **AWS Lambda** - Automated incident containment
- **EventBridge** - Security event routing
- **AWS Systems Manager** - Automated remediation

### 4. Data Protection Layer
- **KMS Encryption** - End-to-end data encryption
- **S3 Bucket Policies** - Enforced encryption & access controls
- **EBS Snapshots** - Forensic evidence preservation

### 5. Network & Application Layers
- **AWS WAF** - Web application firewall
- **Application Load Balancer** - Traffic distribution
- **Auto Scaling Groups** - Self-healing infrastructure
