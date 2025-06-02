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
from botocore.exceptions import ClientError
from typing import Dict
import json
from datetime import datetime, timezone

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
securityhub = boto3.client('securityhub')
sts = boto3.client('sts')

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

# Validate encryption status of upload
def check_encryption(bucket: str, key: str)-> dict:
   """ 
   Validates S3 Object encryption against defined compliance requirements

   Args:
    bucket (str): Name of the S3 bucket
    key (str): Object key within the bucket

    Returns:
        dict: {
        "bucket": str,
        "key": str,
        "encryption": str,
        "kms_key_id": str,
        "compliant": bool
        "standards": list
        }

    Raises:
        EncryptionViolation: if the object fails encryption compliance checks.
   """

   try:
      # Get the bucket and key information 
      response = s3.head_object(Bucket=bucket, Key=key)

      # Get the encryption information of the object
      encryption = response.get("ServerSideEncryption")

      # Get KMS key ID
      kms_key_id = response.get("SSEKMSKeyId")

      # Raise exception if encryption is missing or unsupported
      if encryption not in REQUIRED_ENCRYPTION:
         raise EncryptionViolations(bucket, key, encryption)
      
      # Validate KMS key 
      if encryption == "aws:kms" and not validate_kms_key(kms_key_id):
         raise EncryptionViolations(
            bucket,
            key,
            f"Invalid KMS ARN : {kms_key_id}"
         )
      
      return{
         "bucket": bucket,
        "key": key,
        "encryption": encryption,
        "kms_key_id": kms_key_id,
        "compliant": True,
        "standards":COMPLIANCE_STANDARDS
      }
   
   except ClientError as e:
      raise EncryptionViolations(
         bucket,
         key,
         f"AWS API Error: {str(e)}"
      )

# Report violation to security hub

def report_to_security_hub(violation: Dict) -> Dict:
    """
    Reports S3 encryption compliance violation to Security Hub

    Args:
        violation (dict): {
            "bucket": str,
            "key": str,
            "message": str,
            "standards": List[str]
            "severity": SeverityLevel
        }

    Returns: 
        dict: Security Hub API response
    """

    try:
    # Get the caller account id and current region
        account_id = sts.get_caller_identity()["Account"]
        region = boto3.session.Session().region_name

        return securityhub.batch_import_findings(
           Findings = [{
              "SchemaVersion": "2018-10-08",
              "Id": f"s3-encryption-violation-{violation['bucket']}-{violation['key']}",
              "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
              "GeneratorId": "S3EncryptionChecker",
              "Title": "Non-Compliant S3 Encryption",
              "Description": violation["message"],
              "Severity": {
                 "Label": "CRITICAL" if violation["severity"] == SeverityLevel.CRITICAL
                 else "HIGH"},
              "Resources": [{
                 "Type": "AwsS3Object",
                 "Id": f"arn:aws:s3:::{violation['bucket']}/{violation['key']}",
                 "Region": region
              }],
              "Compliance": {
                 "Status": "FAILED",
                 "RelatedRequirements": violation.get("standards",[])
              },
              "Workflow": {"Status": "NEW"},
              "RecordState":"ACTIVE",
              "FindingProviderFields": {
                 "Severity": {"Label": "HIGH"},
                 "Types": ["Software and Configuration Checks/AWS Security Best Practices"]
              }
           }]
        )
    except ClientError as e:
       print(f"Security Hub Error: {str(e)}")
       raise
    
# Compliance Logging
def log_compliance_event(
      message: str,
      severity: SeverityLevel,
      **metadata
) -> None:
   """
   Logs GRC event and reports critical severity findings to Security Hub.

   Args: 
      message (str): Description of the event
      severity: Enum indicating SeverityLevel
      **metadata: Additional event information
   """

   log_entry = {
      "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
      "severity": severity.name,
      "message": message,
      **metadata
   }

   print(json.dumps(log_entry, indent=2))

   # Send critical and high findings to Security Hub
   if severity == SeverityLevel.HIGH:
      report_to_security_hub({
         **metadata,
         "message": message,
         "standards": COMPLIANCE_STANDARDS,
         "severity": severity
      })
