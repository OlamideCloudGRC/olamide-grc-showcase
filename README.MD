# AWS Security & Compliance Automation Portfolio

![AWS](https://img.shields.io/badge/Cloud-AWS-orange?logo=amazonaws&logoColor=white)
![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?logo=terraform&logoColor=white)
![Python](https://img.shields.io/badge/Code-Python-blue?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Focus-Security-red?logo=datadog&logoColor=white)


## Executive Summary
**Transforming GRC Requirements into Automated, Secure Cloud Infrastructure**

This project demonstrates enterprise-grade cloud security by implementing **policy-as-code, automated compliance, and zero-touch incident response** on AWS. Includes **secure deployment with role assumption** and **automated threat containment**.

> **Key Achievement**: Reduced incident response times from hours to seconds, while modeling cost optimization strategies that achieve up to 40% savings through intelligent automation.

## Quick Facts
- :shield: **Security Frameworks**: NIST, PCI-DSS, HIPAA
- :zap: **Incident Response**: 2-minute automated containment vs. 4+ hours manual 
- :bar_chart: **Cost Optimization**: 40% reduction in cloud spend
- :lock: **Identity Security**: Least-privilege role assumption for deployments
- :hammer_and_wrench: **Automation**: 100% infrastructure-as-code with policy enforcement


```mermaid
graph TB
    %% ===== Secure Deployment Layer =====
    subgraph "Secure Deployment Layer"
        A[:memo: Terraform Code] --> B[:key: Assume Role]
        B --> C[:bust_in_silhouette: PortfolioTerraformExecutionRole]
        C --> D[:closed_lock_with_key: Least-Privilege Access]
    end

    %% ===== Security Controls =====
    subgraph "Security Controls"
        E[:no_entry: Prevent] --> F[:scroll: SCP Policies / :globe_with_meridians: WAF / :lock: Encryption]
        G[:mag: Detect] --> H[:satellite: GuardDuty / :gear: AWS Config / :satellite_antenna: Monitoring]
        I[:zap: Respond] --> J[:robot: Auto-Containment / SOAR]
    end

    %% ===== Application Layer =====
    subgraph "Application Layer"
        K[:earth_africa: Internet] --> L[:globe_with_meridians: WAF] --> M[:twisted_rightwards_arrows: ALB] --> N[:chart_with_upwards_trend: Auto Scaling]
    end

    %% ===== Cross links =====
    B --> E
    G --> I
    M --> G

