"""
AWS Lambda: S3 Encryption Compliance Checker
Features:
    - Strict SSE-KMS validation with KMS ARN checking
    - Custom exception handling for compliance violations
    - Security Hub integration
    - Multi-standard compliance tracking (PCI, NIST, HIPAA)
    - Risk-prioritized logging

"""


#----------Constants----------#
COMPLIANCE_STANDARDS = [
    # Encryption of stored PANS
    "PCI-DSS 4.0 Requirement 3.3.1",

    # Encryption of data at rest 
    "NIST 800-53 SC-28",

    # Encryption of ePHI
    "HIPAA 164.312(a)(2)(iv)"
]

# Listing the required encryptions
REQUIRED_ENCRYPTION = ["aws:kms"]