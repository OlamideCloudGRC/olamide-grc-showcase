"""
AWS Lambda function for KMS Key Rotation Compliance Check
This function checks if the KMS key automatic rotation is enabled
"""

#==========================================#
#                Module Imports            #
#==========================================#
import boto3
from enum import IntEnum
from datetime import datetime, timezone
import json
import os
from botocore.config import Config
import traceback

#==========================================#
#       Class Definitions                  #
#==========================================#
class SeverityLevel(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


#==========================================#
#             Service Clients              #
#==========================================#
# Initialize KMS Client
kms_client = boto3.client('kms', config=Config(
    retries ={'max_attempts':3, 'mode':'adaptive'},
    connect_timeout = 10,
    read_timeout = 30
))


#==========================================#
#       Function Definitions               #
#==========================================#
# Logging function for compliance
def log_compliant_event(
        message: str,
        severity: SeverityLevel,
        **metadata  
    ) -> None:
    """
    Logs a compliance-related event with timestamp, 
    severity and additional metadata in structured JSON format
    """

    log_entry = {
     "timestamp": datetime.now(timezone.utc).isoformat(),
     "severity": severity.name,
     "message": message,
     **metadata
    }
    print(json.dumps(log_entry))


# KMS key rotation check
def check_key_rotation(kms_client, key_id):
    """
    Checks whether automatic key rotation is enabled for the specified KMS Keys

    Returns:
        (bool, str): Tuple indicating status and message
    """
    try:
        response = kms_client.get_key_rotation_status(KeyId=key_id)
        if not response['KeyRotationEnabled']:
            return False, "Key rotation disabled"
        return True, "Key rotation enabled"   
    
    except kms_client.exceptions.NotFoundException:
        return False, "Key not found"
    
    except kms_client.exceptions.DisabledException:
        return False, "Key disabled"
    
    except Exception as e:
        return False, f"API error: {str(e)}"

    
# Lambda handler
def lambda_handler(event, context):
    """
    AWS Lambda function to check automatic KMS key rotation status.

    - Fetches key metadata using describe_key
    - Checks if key rotation is enabled
    - Logs non-compliant keys and errors
    """
    
    # Get monitored keys from environment variable (JSON list)
    monitored_keys = json.loads(os.getenv('MONITORED_KEYS', '[]'))
    results = []

    # Fetch key metadata
    for key in monitored_keys:
        try:
            key_info = kms_client.describe_key(KeyId=key)
            key_id = key_info['KeyMetadata']['KeyId']

            # Check key rotation compliance
            is_compliant, reason = check_key_rotation(kms_client, key_id)
            
            # Store compliance result
            result = {
                "key_id": key_id,
                "key_alias": key,
                "compliant": is_compliant,
                "reason": reason,
                "last_checked": datetime.now(timezone.utc).isoformat()
            }
            results.append(result)

            # Log violation if non_compliant
            if not is_compliant:
                log_compliant_event(
                    message = "KMS rotation violation",
                    severity = SeverityLevel.HIGH,
                    **result
                )

        except Exception as e:
            # Log unexpected failure in key check
            log_compliant_event(
                message = "Key check failed",
                severity = SeverityLevel.MEDIUM,
                key = key,
                error =str(e),
                stack_trace = traceback.format_exc()
            )
            
    return{
        "status": "COMPLETED",
        "keys_checked": len(monitored_keys),
        "non_compliant_keys": sum(1 for r in results if not r["compliant"]),
        "details": results
    }

    


        