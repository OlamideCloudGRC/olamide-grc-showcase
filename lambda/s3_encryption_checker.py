"""
AWS Lambda: S3 Encryption Compliance Checker
Features:
    - Strict SSE-KMS validation with KMS ARN checking
    - Custom exception handling for compliance violations
    - Security Hub integration
    - Multi-standard compliance tracking (PCI, NIST, HIPAA)
    - Risk-prioritized logging

"""
#==========================================#
#                Module Imports            #
#==========================================#
import boto3
from enum import IntEnum


#==========================================#
#                Constants                 #
#==========================================#
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


#==========================================#
#             Service Clients              #
#==========================================#
s3 = boto3.client('s3')

#==========================================#
#       Class Definitions                  #
#==========================================#

# Define the severity levels Enum class
class SeverityLevel(IntEnum):
   CRITICAL = 4  # Compliance Violations
   HIGH = 3      # Security misconfiguration
   MEDIUM = 2    # Operational warnings
   LOW = 1       # Informational

# Define Encryption violations Exception class
class EncryptionViolations(Exception):
   def __init__(self, bucket: str, key:str, found_encryption: str):
      self.bucket = bucket
      self.key = key
      self.found_encryption = found_encryption
      super().__init__(
         f"Non-compliant encryption in s3://{bucket}/{key}. "
         f"Found: {found_encryption}, Required: {REQUIRED_ENCRYPTION}"
      )


#==========================================#
#       Function Definitions               #
#==========================================#
# Validate KMS key ARN to ensure accurate encryption compliance 
def validate_kms_key(key_arn: str) -> bool:
   return bool(
      key_arn and
      key_arn.startswith("arn:aws:kms:") and
      ":key/" in key_arn
   )