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


#==========================================#
#       Class Definitions                  #
#==========================================#
class SeverityLevel(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


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

    log_entry={
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
    
    except Exception as e:
        return False, f"Check failed: {str(e)}"

    
