# Technical Risk Assessment Report
**Project:** AWS Security & Compliance Automation Portfolio
**Date:** October 26, 2023
**Author:** Olamide Solola, Cloud Security & GRC Professional

## 1. Introduction
This report assesses the security risks addressed by the automated GRC portfolio. The analysis follows a qualitative methodology, evaluating risks based on likelihood and impact to the confidentiality, integrity, and availability (CIA) triad.

## 2. Risk Assessment Methodology
- **Framework:** NIST SP 800-30
- **Impact Scale:** Low, Medium, High, Critical
- **Likelihood Scale:** Low, Medium, High
- **Risk Level:** Calculated as (Impact x Likelihood)

## 3. Inherent Risk Assessment & Mitigations

| ID | Risk Description | Impact | Likelihood | Inherent Risk | Control / Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **R-001** | Unencrypted sensitive data stored in S3 | High | Medium | High | **Preventive:** S3 Bucket Policy denies `PutObject` without `aws:kms`. **Detective:** Lambda function checks encryption on upload. **Corrective:** Auto-remediation applies SSE-KMS. | Low |
| **R-002** | Compromised EC2 instance leads to data exfiltration | Critical | Medium | High | **Corrective:** Automated containment (ELB drain, SG quarantine, termination). **Detective:** GuardDuty monitoring. **Recovery:** ASG auto-replaces instance. | Low |
| **R-003** | Non-compliant resource deployment violating tagging policy | Medium | High | High | **Preventive:** AWS Organizations SCPs block creation of untagged S3 buckets. **Detective:** AWS Config rule `s3-bucket-tagging-check`. | Low |
| **R-004** | KMS key rotation disabled, weakening crypto posture | Medium | Low | Medium | **Detective:** Scheduled Lambda function checks key rotation status. **Corrective:** SNS alerts to security team. | Low |
| **R-005** | SSL/TLS certificate expiration causing service outage | High | Medium | High | **Detective:** ACM monitoring with EventBridge rules for expiry. **Preventive:** Automated DNS validation and renewal. | Low |
| **R-006** | DDoS or brute-force attack on web application | High | Medium | High | **Preventive:** AWS WAF with rate-based rules, geo-blocking, and managed rule sets. **Detective:** CloudWatch alarms on blocked requests. | Medium |

## 4. Risk Treatment Strategy
The primary strategy is **Risk Mitigation**, achieved through a defense-in-depth architecture of automated, native AWS controls. All high inherent risks have been reduced to low residual risk.

## 5. Conclusion & Recommendation
The implemented security controls have effectively minimized the identified risks to an acceptable level. The shift-left and automate-everything approach transforms security from a manual, audit-time burden to a continuous, automated process.
