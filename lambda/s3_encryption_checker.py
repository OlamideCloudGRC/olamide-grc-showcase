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
import time
from datetime import datetime, timezone
import traceback
from botocore.config import Config
import os

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
securityhub = boto3.client('securityhub', config=Config(
   retries = {
      'max_attempts': 3,
      'mode': 'adaptive'
   },
   connect_timeout = 10,
   read_timeout = 30
))
sts = boto3.client('sts')
cloudwatch = boto3.client('cloudwatch')


#==========================================#
#       Class Definitions                  #
#==========================================#

# Define the severity levels Enum class
class SeverityLevel(IntEnum):
   CRITICAL = 4  # Compliance Violations (e.g., unencrypted upload)
   HIGH = 3      # Security misconfiguration (e.g., misconfigured KMS policies)
   MEDIUM = 2    # Operational warnings (e.g., timeouts or retries)
   LOW = 1       # Informational (e.g., successful encryption check)

# Define Encryption violations Exception class
class EncryptionViolations(Exception):
   def __init__(self, bucket: str, key:str, found_encryption: str, severity: SeverityLevel, message:str = None):
      default_msg = message or f"{severity.name} violation in s3://{bucket}/{key}. Found:{found_encryption}, Required: {REQUIRED_ENCRYPTION}"
      super().__init__(default_msg)
      self.bucket = bucket
      self.key = key
      self.found_encryption = found_encryption or "None"
      self.severity= severity
      


#==========================================#
#       Function Definitions               #
#==========================================#
# Check if Security Hub is enabled
def is_security_hub_enabled() -> bool:
   """
   Checks if AWS Security Hub is enabled in the current region/account

   Returns:
      bool: True if Security Hub is enabled, False otherwise
   """
   try:
      response = securityhub.describe_hub()
      return True
   
   except securityhub.exceptions.ResourceNotFoundException:
      return False
   
   except ClientError as e:
      log_compliance_event(
         message= f"Error checking Security Hub status: {str(e)}",
         severity= SeverityLevel.MEDIUM
      )
      return False

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

   print(f"Checking encryption on: s3://{bucket}/{key}")
   try:
      # Get the bucket and key information 
      response = s3.head_object(Bucket=bucket, Key=key)
      print("[check_encryption] head_object response recieved")
      print(json.dumps(response, default=str, indent=2))

      # Get the encryption information of the object
      encryption = response.get("ServerSideEncryption")

      # Get KMS key ID
      kms_key_id = response.get("SSEKMSKeyId")

      print(f"[check_encryption] ServerSideEncryption: {encryption}")
      print(f"[check_encryption] SSEKMSKeyId: {kms_key_id}")

      # No Encryption (CRITICAL)
      print(f"REQUIRED_ENCRYPTION = {REQUIRED_ENCRYPTION}")
      print(f"Encryption used = {encryption}")
      if encryption not in REQUIRED_ENCRYPTION:
         print("[check_encryption] Encryption is NOT compliant. Raising violation...")
         raise EncryptionViolations(
            bucket = bucket,
            key = key, 
            found_encryption= encryption,
            severity= SeverityLevel.CRITICAL,
            message = f"Violates encryption policy: Found {encryption}, Required {REQUIRED_ENCRYPTION}"
            )
      
      # Validate KMS key 
      if encryption == "aws:kms":
         if not validate_kms_key(kms_key_id):
            print("[check_encryption] KMS key validation FAILED")
            raise EncryptionViolations(
               bucket= bucket,
               key= key,
               found_encryption= f"Invalid KMS ARN : {kms_key_id}",
               severity= SeverityLevel.HIGH,
               message= "Invalid KMS Key configuration"
            )
         else: 
            print("[check_encryption] KMS key validation PASSED")

      print("[check_encryption] Object encryption is COMPLIANT")

      return{
         "bucket": bucket,
        "key": key,
        "encryption": encryption,
        "kms_key_id": kms_key_id,
        "compliant": True,
        "standards":COMPLIANCE_STANDARDS
      }
   
   except ClientError as e:
      print("[check_encryption] ClientError encountered")
      print(str(e))

      raise EncryptionViolations(
         bucket= bucket,
         key= key,
         found_encryption="UNKNOWN",
         severity= SeverityLevel.HIGH,
         message= f"AWS API Error: {str(e)}"
      )

# Report violation to security hub

def report_to_security_hub(violation: Dict) -> Dict:
    """
    Reports S3 encryption compliance violation to Security Hub with:
    - Automatic retries
    - Detailed error logging
    - Compliance-standard mapping

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
    # Check if Security Hub is enabled before proceeding
    if not is_security_hub_enabled():
         log_compliance_event(
            message= "Security Hub is not enabled - skipping finding submission",
            severity= SeverityLevel.MEDIUM,
            bucket= violation.get("bucket"),
            key= violation.get("key")
          )
         return None


    try:
      # Severity level mapping for API with fail-safe default
      severity_mapping = {
         SeverityLevel.CRITICAL: "CRITICAL",
         SeverityLevel.HIGH: "HIGH",
         SeverityLevel.MEDIUM: "MEDIUM",
         SeverityLevel.LOW: "LOW"
      }  

      # Get severity label
      severity_label = severity_mapping.get(violation["severity"])

      # Log unmapped severity values
      if severity_label is None:
         print(f"[SecurityHub] Unmapped severity level: {violation['severity']}. Defaulting to HIGH.")
         severity_label = "HIGH"


      # Get the caller account id and current region
      account_id = sts.get_caller_identity()["Account"]
      region = boto3.session.Session().region_name

      now = datetime.now(timezone.utc).isoformat()
      finding_tag = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
      finding_id = f"s3-encryption-violation-{violation['bucket']}-{violation['key']}-{finding_tag}"

      response= securityhub.batch_import_findings(
         Findings = [{
              "SchemaVersion": "2018-10-08",
              "Id": finding_id,
              "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
              "GeneratorId": "S3EncryptionChecker",
              "AwsAccountId": account_id,
              "CreatedAt": now,
              "UpdatedAt": now,
              "Title": "Non-Compliant S3 Encryption",
              "Description": violation["message"],
              "Resources": [{
                 "Type": "AwsS3Object",
                 "Id": f"arn:aws:s3:::{violation.get('bucket')}/{violation.get('key')}",
                 "Partition": "aws",
                 "Region": region
              }],
              "Compliance": {
                 "Status": "FAILED",
                 "RelatedRequirements": violation.get("standards",[])
              },
              "Workflow": {"Status": "NEW"},
              "RecordState":"ACTIVE",
              "FindingProviderFields": {
                 "Severity": {"Label": severity_label},
                 "Types": ["Software and Configuration Checks/AWS Security Best Practices"]
              }
           }]
        )
      
      # Log successful submission for audit trail
      log_compliance_event(
         message= "Security Hub submission succeeded",
         severity= SeverityLevel.LOW,
         reason= "Successful first-attempt delivery to Security Hub",
         finding_id= finding_id
      )

      return response
    
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

   print("Logging compliant event")
   print(json.dumps(log_entry, indent=2))

   # Send critical and high findings to Security Hub
   if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
      # Only report if Security Hub is enabled
      if is_security_hub_enabled():
         report_to_security_hub({
            **metadata,
            "message": message,
            "standards": COMPLIANCE_STANDARDS,
            "severity": severity
      })
      
      else:
         log_compliance_event(
            message= "Skipping Security Hub report - service not enabled",
            severity= SeverityLevel.MEDIUM,
            **metadata
         )


# Auto-remediate unencrypted S3 objects by applying SSE-KMS
def remediate_unencrypted_object(bucket:str, key:str) -> Dict:
   """
   Applies SSE-KMS encryption to non-compliant S3 objects.
   Returns remediation status for logging
   """

   try:
      print(f"[remediation] Using KMS key alias: {os.environ.get('KMS_KEY_ALIAS', 'alias/aws/s3')}")
      # Copy object into itself with encryption (preserves metadata)
      s3.copy_object(
         Bucket= bucket,
         Key= key,
         CopySource= {"Bucket":bucket, "Key":key},
         ServerSideEncryption= "aws:kms",
         SSEKMSKeyId= os.environ.get("KMS_KEY_ALIAS", "alias/aws/s3"),
         MetadataDirective= "COPY"
      )

      return {
         "status": "SUCCESS",
         "action": "Applied SSE-KMS encryption",
         "bucket": bucket,
         "key": key

      }
   
   except ClientError as e:
      print(f"[remediation] Remediation error: {str(e)}")
      return {
         "status": "FAILED",
         "error": str(e),
         "bucket": bucket,
         "key": key
      }

# Emit custom CloudWatch metrics for compliance findings
def emit_cloudwatch_metrics(findings, context):
   """ 
   Send custom CloudWatch metrics for compliance findings(i.e., violations detected during encryption checks)
   
   Metrics:
   - CriticalFindings: Count of findings with severity >= CRITICAL
   - FailedRemediations: Count of findings where remediation_status is "FAILED"

   Each metric includes the Lambda FunctionName as a dimension.
   """
   
   try:
      cloudwatch.put_metric_data(
         Namespace = "GRC/Compliance",
         MetricData = [
            {
               "MetricName" : "CriticalFindings",
               "Dimensions" : [
                  {
                     "Name" : "FunctionName",
                     "Value" : context.function_name
                  }
               ],
               "Value" : len([f for f in findings if f['severity'] >= SeverityLevel.CRITICAL]),
               "Unit" : "Count"
            },
            {
               "MetricName" : "FailedRemediations",
               "Dimensions" : [
                  {
                     "Name" : "FunctionName",
                     "Value" : context.function_name
                  }
               ],
               "Value" : len([f for f in findings if f.get("remediation_status") == "FAILED"]),
               "Unit" : "Count"
            }
         ]
      )

   except ClientError as e:
      log_compliance_event(
         message = f"CloudWatch Metrics Error: {str(e)}",
         severity = SeverityLevel.MEDIUM

      )



# Define Lambda handler
def lambda_handler(event: Dict, context) -> Dict:
   """
   For Lambda execution

   Args:
      event: S3 PutEvent notification
      context: Lambda execution context

   Returns:
      dict: {
      "statusCode": int,
      "body": {
         "processed": int,
         "violations": List[Dict],
         "remediations": List[Dict],
         "timestamp": str,
         "duration_ms": float,
         "compliance_status": str
         "standards": List[str]
         }
      }
   """
   print("Lambda triggered. Event:")
   print(json.dumps(event, indent=2))
   
   # Record start time for encryption check duration tracking
   start_time = time.time()

   # Creating a list to capture violations and remediations
   violations = []
   remediations = []

   # Check remaining time (fail fast if insufficient)
   if context.get_remaining_time_in_millis()< 5000:
      log_compliance_event(
         "Insufficient Lambda timeout remaining",
         SeverityLevel.MEDIUM
      )
      raise TimeoutError("Less than 5 seconds remaining")

   for record in event.get("Records", []):
      try:
         bucket = record["s3"]["bucket"]["name"]
         key =record["s3"]["object"]["key"]

         try:
            result = check_encryption(bucket, key)
            print("Encryption result returned:")
            print(result)
            print("Encrypyption check passed, now logging compliance event")
            
            try:
               log_compliance_event(
                  f"Compliant encryption: s3://{bucket}/{key}",
                  SeverityLevel.LOW,
                  **result
               )
               print("Compliance log for successful encryption done")
               
            except Exception as e:
               print("Error during log_compliance_event")
               print(str(e))


         except EncryptionViolations as e:
            print("Encryption violation caught")
            violation= {
               "bucket": e.bucket,
               "key": e.key,
               "error": str(e),
               "severity":e.severity
            }
            violations.append(violation)


            # Auto-remediate CRITICAL severity level (unencrypted objects)
            if e.severity == SeverityLevel.CRITICAL:
               remediation_status = remediate_unencrypted_object(bucket, key)
               remediation_status.update({
                  "original_violation": violation
               })
               remediations.append(remediation_status)


               log_compliance_event(
                  f"Remediation attempt: {remediation_status['status']}",
                  severity= SeverityLevel.LOW if remediation_status['status'] == "SUCCESS" else SeverityLevel.CRITICAL,
                  bucket= e.bucket,
                  key= e.key,
                  found_encryption= e.found_encryption
               )

         except Exception as e:
            print ("Unexpected error during encryption check")
            print(str(e))
            violations.append({
               "bucket" : bucket,
               "key" : key,
               "error" : f"unexpected error {str(e)}",
               "severity" : SeverityLevel.HIGH
            })

      except KeyError as e:
         log_compliance_event(
            "Malformed S3 event record",
            SeverityLevel.MEDIUM,
            error= f"Missing key: {str(e)}",
            raw_event= record
         )

      except Exception as e:
         log_compliance_event(
            f"Unexpected error processing record: {str(e)}",
            SeverityLevel.HIGH,
            error_type=e.__class__.__name__,
            traceback= traceback.format_exc()
         )

         violations.append({
            "bucket": "UNKNOWN",
            "key": "UNKNOWN",
            "error": f"Processing failed: {str(e)}",
            "severity": SeverityLevel.HIGH 
         })

   # Record end time for encryption check
   end_time = time.time()

   # Calculate duration in milliseconds (rounded to 2 decimal places)
   duration_ms = round((end_time - start_time) * 1000, 2)

   # Generate current UTC timestamp in ISO format (with milliseconds)
   timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds')

   # Emit custom metrics to Cloudwatch based on violation findings
   emit_cloudwatch_metrics(violations, context)

   print("Lambda execution completed")

   return{
      "statusCode": 200 if not violations else 207,
      "body": {
         "processed": len(event.get("Records",[])),
         "violations": violations,
         "remediations": remediations,
         "compliance_status": "PASS" if not violations else "FAIL",
         "timestamp": timestamp,
         "duration_ms": duration_ms,
         "standards": COMPLIANCE_STANDARDS
      }
   } 