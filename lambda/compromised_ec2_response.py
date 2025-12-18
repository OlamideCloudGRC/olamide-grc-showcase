
"""
AWS Lambda: Automated EC2 Compromise Response
Triggered primarily by GuardDuty findings via EventBridge.
Features:
    - Automated Containement (ELB deregistration, ASG detachment, network quarantine)
    - Forensic evidence preservation (EBS Snapshots)
    - Security Hub integration with compliance mapping
    - Multi-standard compliance tracking (CIS, NIST, PCI)
    - Risk-prioritized logging and error handling
    - Idempotent operations for retry safety
"""

#==========================================#
#                Module Imports            #
#==========================================#
import boto3
from enum import IntEnum
from botocore.config import Config
from datetime import datetime, timezone
from botocore.exceptions import ClientError
from typing import Dict, List, Optional
import time
import json
import traceback
import os


#==========================================#
#                Constants                 #
#==========================================#
# Compliance standards mapped to automated detection, containment,
# and incident response controls for audit traceability.

COMPLIANCE_STANDARDS = [
    # Detect unauthorized activity and enable corrective action
    "CIS AWS Foundation 2.2", 

    # Automated incident detection, containment, and reporting
    "NIST 800-53 IR-4",

    # Respond to and contain security incidents
    "PCI-DSS 4.0 Requirement 12.10"
]

# Define the default quarantine security group name
QUARANTINE_SG_NAME = "compromise-response-quarantine-sg"


#==========================================#
#             Service Clients              #
#==========================================#
"""Establish connection with the needed services"""
securityhub = boto3.client('securityhub', config=Config(
   retries = {
      'max_attempts': 3,
      'mode': 'adaptive'
   },
   connect_timeout = 10,
   read_timeout = 30
))
ec2=boto3.client('ec2')
elbv2=boto3.client('elbv2')
autoscaling = boto3.client('autoscaling')
sts = boto3.client('sts')
cloudwatch = boto3.client('cloudwatch')



#==========================================#
#       Class Definitions                  #
#==========================================#
class SeverityLevel(IntEnum):
    """
    Enum for standardizing severity levels across logging,
    Security Hub reporting, and metrics.
    """
    CRITICAL = 4 # Active compromise, immediate containement required
    HIGH = 3     # Successful containement actions
    MEDIUM = 2   # Partial success or non-critical errors
    LOW = 1      # Informational (eg, process started/completed)
    INFO = 0     # Successful execution


# Define Incident response Exception class
class IncidentResponseError(Exception):
   """
   Base exception for incident response failures.

   Custom exceptions allow partial execution tracking and structured
   failure reporting without prematurely terminating the function execution.

   """
   def __init__(self, instance_id: str, action:str, severity: SeverityLevel, message:str):
      super().__init__(message)
      self.instance_id = instance_id
      self.action = action
      self.severity = severity
      self.message= message

# Define containment error exception class
class ContainmentError(IncidentResponseError):
   """Raised when containment actions (ELB/ASG/SG) fail."""
   pass

# Define forensic error exception class
class ForensicError(IncidentResponseError):
   """Raised when forensic evidence collection fails."""
   pass



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
      securityhub.describe_hub()
      return True
   
   except securityhub.exceptions.ResourceNotFoundException:
      return False
   
   except ClientError as e:
      log_incident_event(
         message= f"Error checking Security Hub status: {str(e)}",
         severity= SeverityLevel.MEDIUM
      )
      return False
   
   
# Get the VPC ID
def get_instance_vpc_id(instance_id: str) -> str:
   """
   Retrieves the VPC ID of a given EC2 instance

   Args:
      instance_id(str): The ID of the EC2 instance

   Returns:
      str: The VPC ID of the instance.

   Raises:
      ContainmentError: If the instance cannot be described.
   """
   try:
      response = ec2.describe_instances(InstanceIds=[instance_id])
      return response['Reservations'][0]['Instances'][0]['VpcId']
   
   except ClientError as e:
      raise ContainmentError(
         instance_id=instance_id,
         action="DescribeInstance",
         severity=SeverityLevel.HIGH,
         message=f"Failed to describe instance {instance_id}: {str(e)}"
      )

# Get quarantine security group
def get_quarantine_sg(vpc_id: str) -> str:
   """
   Returns the quarantine SG ID from env or looks it up by name.

   Raises:
      ContainementError: If SG creation or modification fails
   """

   # Prefer explicit SG ID via environment variable for controlled deployments;
   # fall back to name-based lookup to remain environment-agnostic across accounts.
   sg_id =os.getenv("QUARANTINE_SG_ID")
   if sg_id:
      return sg_id
   
   # Fallback: Look up by name + VPC (keeps working even if env not set)
   name = os.getenv("QUARANTINE_SG_NAME", "compromise-response-quarantine-sg")
   try:
      response = ec2.describe_security_groups(
         Filters = [
            {'Name': 'group-name', 'Values': [name]},
            {'Name': 'vpc-id', 'Values':[vpc_id]}
         ]
      )

      if response['SecurityGroups']:
         return response['SecurityGroups'][0]['GroupId']
      
      raise ContainmentError(
         instance_id="N/A",
         action="LookupQuarantineSG",
         severity=SeverityLevel.HIGH,
         message=f"Quarantine SG '{name}' not found in VPC {vpc_id}."
      )
      
   except ClientError as e:
      raise ContainmentError(
         instance_id="N/A",
         action="LookupQuarantineSG",
         severity=SeverityLevel.HIGH,
         message=f"Failed to look up quarantine SG in VPC {vpc_id}: {str(e)}."
      )
   


# Deregister compromised instance from ELB
def deregister_from_elb(instance_id: str) -> None:
   """
   Deregisters a compromised instance from all associated Load Balancer Target Groups.

   Args:
      instance_id(str): The ID of the EC2 instance

   Raises: 
      ContainementError: If deregistration fails.
   """

   vpc_id=get_instance_vpc_id(instance_id)

   try:
      # Get all Target Groups in the instance's VPC
      target_groups=elbv2.describe_target_groups()
      for tg in target_groups['TargetGroups']:
         if tg['VpcId'] == vpc_id:
            # Check if the instance is registered
            targets = elbv2.describe_target_health(
               TargetGroupArn=tg['TargetGroupArn'],
               Targets=[{'Id': instance_id}]
            )

            if targets['TargetHealthDescriptions']:
               elbv2.deregister_targets(
                  TargetGroupArn=tg['TargetGroupArn'],
                  Targets=[{'Id': instance_id}]
               )
               log_incident_event(
                  message=f"Instance deregistered from Target Group: {tg['TargetGroupArn']}",
                  severity=SeverityLevel.INFO,
                  instance_id=instance_id,
                  target_group_arn= tg['TargetGroupArn']
               )

   except ClientError as e:
      raise ContainmentError(
         instance_id=instance_id,
         action="DeregisterFromELB",
         severity=SeverityLevel.HIGH,
         message=f"Failed to deregister instance {instance_id} from ELB: {str(e)}"
      )


# Detach instance from Auto Scaling Group
def detach_from_asg(instance_id: str) -> None:
   """
   Detaches a compromised instance from its Auto Scaling Group.

   Args:
      instance_id(str): The ID of the EC2 instance.

   Raises:
      ContainmentError: If detachment fails
   """

   try:
      # Find the ASG name from instance's tags
      instance_desc = ec2.describe_instances(InstanceIds=[instance_id])
      tags = instance_desc['Reservations'][0]['Instances'][0].get('Tags', [])
      asg_name = None
      for tag in tags:
         if tag['Key'] == 'aws:autoscaling:groupName':
            asg_name = tag['Value']
            break
      
      if not asg_name:
         raise ContainmentError(
            instance_id=instance_id,
            action="DetachFromASG",
            severity=SeverityLevel.HIGH,
            message=f"Instance {instance_id} is not part of an Auto Scaling Group (no ASG tag found)."
         )
      
      autoscaling.detach_instances(
         InstanceIds=[instance_id],
         AutoScalingGroupName=asg_name,
         ShouldDecrementDesiredCapacity=False
      )
      log_incident_event(
         message=f"Instance detached from Auto Scaling Group: {asg_name}",
         severity=SeverityLevel.INFO,
         instance_id=instance_id,
         asg_name=asg_name

      )

   except ClientError as e:
      raise ContainmentError(
         instance_id = instance_id,
         action = "DetachFromASG",
         severity=SeverityLevel.HIGH,
         message=f"Failed to detach instance {instance_id} from ASG: {str(e)}"
      )
   

# Appy Quarantine security group to prevent inbound and outbound
def apply_quarantine_sg(instance_id: str, quarantine_sg_id: str)-> None:
   """
   Applies the quarantine security group to the instance, replacing all existing SGs.

   Args:
      instance_id(str): The ID of the EC2 instance.
      quarantine_sg_id(str): The ID of the quarantine security group.

   Raises:
      ContainmentError: If applying the security group fails.
   """

   try:
      ec2.modify_instance_attribute(
         InstanceId=instance_id,
         Groups=[quarantine_sg_id]
      )
   
   except ClientError as e:
      raise ContainmentError(
         instance_id=instance_id,
         action="ApplyQuarantineSG",
         severity=SeverityLevel.CRITICAL,
         message=f"Failed to apply quarantine SG to instance{instance_id}:{str(e)}"
      )


# Take snapshot of EBS volume of compromised instance
def take_forensic_snapshot(instance_id: str) -> List[Dict]:
   """
   Takes snapshots of all EBS volumes attached to the instance for forensic analysis.

   Args:
      instance_id(str): The ID of the EC2 instance.

   Returns:
      List[Dict]: A list of snapshot metadata.

   Raises:
      ForensicError: If snapshot creation fails
   """      
   
   snapshots = []

   try:
      instance_desc = ec2.describe_instances(InstanceIds=[instance_id])
      volumes = instance_desc['Reservations'][0]['Instances'][0]['BlockDeviceMappings']

      for vol in volumes:
         if 'Ebs' in vol:
            vol_id = vol['Ebs']['VolumeId']
            snapshot_desc = f"Forensic snapshot for compromised instance {instance_id}. Created by automated incident response"
            snapshot = ec2.create_snapshot(
               VolumeId=vol_id,
               Description=snapshot_desc,
               TagSpecifications=[{
                  'ResourceType': 'snapshot',
                  'Tags': [
                     {'Key': 'Name', 'Value': f'forensic-{instance_id}'},
                     {'Key': 'SourceInstance', 'Value':instance_id},
                     {'Key': 'IncidentResponse', 'Value': 'Automated'},
                     {'Key': 'ForensicEvidence', 'Value': 'True'},
                     {'Key': 'Retention', 'Value':'DoNotDelete'}
                  ]
               }]
            )

            snapshots.append({
               'SnapshotId': snapshot['SnapshotId'],
               'VolumeId': vol_id,
               'StartTime': snapshot['StartTime'].isoformat()
            })

      return snapshots
      
   except ClientError as e:
      raise ForensicError(
         instance_id=instance_id,
         action="CreateSnapshot",
         severity=SeverityLevel.HIGH, # Losing evidence is high severity
         message=f"Failed to create forensic snapshot for instance {instance_id}: {str(e)}"
      )


# Terminate compromised instance
def terminate_instance(instance_id: str) -> None:
   """
   Terminates the compromised instance. The ASG will launch a replacement.

   Args:
      instance_id(str): The ID of the EC2 instance.

   Raises:
      ContainmentError: If termination fails.
   """

   try:
      ec2.terminate_instances(InstanceIds=[instance_id])

   except ClientError as e:
      raise ContainmentError(
         instance_id=instance_id,
         action="TerminateInstance",
         severity=SeverityLevel.HIGH,
         message=f"Failed to terminate instance {instance_id}: {str(e)}"
      )
      

# Report incident to security hub
def report_to_security_hub(violation: Dict) -> Dict:
   """
   Reports the incident response actions to AWS Security Hub.

   Args:
      violation(dict): Contains details of the incident and response.

   Returns:
      dict: Security Hub API response.
   """

   # Security Hub reporting is optional. If its not enabled, skip reporting
   # instead of throwing avoidable boto3 error
   if not is_security_hub_enabled():
      return None
   
   try:
      # Pull account + region dynamically so this works accross environments
      account_id = sts.get_caller_identity()["Account"]
      region = boto3.session.Session().region_name

      # Security Hub expects ISO timestamps in UTC
      now = datetime.now(timezone.utc).isoformat()


      # My code uses IntEnum severity, but Security Hub expects string labels.
      # This mapping keeps the convertion clean and centralized
      severity_mapping = {
         SeverityLevel.CRITICAL: "CRITICAL",
         SeverityLevel.HIGH: "HIGH",
         SeverityLevel.MEDIUM: "MEDIUM",
         SeverityLevel.LOW: "LOW",
         SeverityLevel.INFO: "INFORMATIONAL"
      }

      # If severity is missing/unexpected, default to HIGH
      # so we don't accidentally under-report an incident
      severity_label = severity_mapping.get(violation["severity"], "HIGH")

      # Build a unique finding ID so multiple incidents don't overwrite each other.
      # Timestamp helps uniqueness
      finding_id = f"incident-response-{violation['instance_id']}-{int(time.time())}"

      response = securityhub.batch_import_findings(
         Findings = [{
            # Required schema version for Security Hub findings.
            "SchemaVersion": "2018-10-08",

            # Unique ID for this finding.
            "Id": finding_id,

            # Identifies the "Product" submitting the finding.
            # Using the default product ARN for this Account
            "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",

            # Identifies what generated the finding
            "GeneratorId": "EC2IncidentResponse",

            # The AWS account where the incident occurred.
            "AwsAccountId": account_id,

            "CreatedAt": now,
            "UpdatedAt": now,

            # Human readable summary.
            "Title": f"Automated Response: Compromised EC2 Instance {violation['instance_id']}",
            "Description": violation["message"],

            # Tie the finding to the actual compromised instance.
            "Resources": [{
               "Type": "AwsEc2Instance",
               "Id":f"arn:aws:ec2:{region}:{account_id}:instance/{violation['instance_id']}",
               "Partition": "aws",
               "Region": region
            }],

            # Mark as failed because this represents a security incident/policy validation.
            # RelatedRequirements attaches CIS/NIST/PCI mapping for audit traceability.
            "Compliance":{
               "Status": "Failed",
               "RelatedRequirements": violation.get("standards", [])
            },

            # Marked as RESOLVED as we ve contained it by the time of the report.
            # This finding is mainly for visibility/audit, not an open ticket
            "Workflow":{"Status": "RESOLVED"},

            # Archive so it's recorded but not constantly showing as an active issue.
            "RecordState": "ARCHIVED",

            # Put severity + classification in the security Hub expected format.
            "FindingProviderFields": {
               "Severity": {"Label": severity_label},
               "Types": ["Effects/Compromised Instance", "Unusual Behaviors/ Instance"]
            }
         }]
      )

      return response
   
   except ClientError as e:
      log_incident_event(
         message=f"Security Hub submission failed: {str(e)}",
         severity=SeverityLevel.MEDIUM,
         instance_id=violation.get('instance_id', 'UNKNOWN')
      )

      raise



# Log incident events
def log_incident_event(message:str, severity: SeverityLevel, **metadata) -> None:
   """
   Centralized logging for all incident response events.

   Args:
      message (str): The log message.
      severity (SeverityLevel): The severity of the event.
      **metadata: Additional key-value pairs for context
   """
   log_entry = {
      "timestamp": datetime.now(timezone.utc).isoformat(),
      "severity": severity.name,
      "message": message,
      **metadata
   }
   print(json.dumps(log_entry, indent=2))

   # Only HIGH and CRITICAL events are escalated to Security Hub 
   # to reduce alert fatigue and focus on actionable incidents.
   
   if severity >= SeverityLevel.HIGH:
      report_to_security_hub({
         **metadata,
         "message": message,
         "standards": COMPLIANCE_STANDARDS,
         "severity": severity
      })


# Emit cloudwatch metrics
def emit_cloudwatch_metrics(actions: List[Dict], context) -> None:
   """ 
   Emits custom Cloudwatch metrics for monitoring response actions.

   Args:
      actions(List[Dict]): List of actions taken during the response.
      context: Lambda context object.
   """

   try:
      # Count critical containment actions
      critical_actions = len([a for a in actions if a.get('severity') == SeverityLevel.CRITICAL])

      # Count instances where evidence was preserved
      evidence_actions = len([a for a in actions if a.get('action') == 'CreateSnapshot'])

      cloudwatch.put_metric_data(
         Namespace="IR/EC2Compromise",
         MetricData=[
            {
               "MetricName": "ContainmentActions",
               "Dimensions": [{"Name": "FunctionName", "Value":context.function_name}],
               "Value": critical_actions,
               "Unit": "Count"
            },
            {
               "MetricName":"EvidencePreservationActions",
               "Dimensions": [{"Name": "FunctionName", "Value":context.function_name}],
               "Value": evidence_actions,
               "Unit": "Count"
            }
         ]
      )

   except ClientError as e:
      log_incident_event(
         message=f"Failed to emit CloudWatch metrics: {str(e)}",
         severity=SeverityLevel.MEDIUM
      )


# Function to find instance ID in various event formats
def find_instance_id_in_event(event: Dict) -> Optional[str]:
   """ Attempt to extract instance ID from various event patterns"""

   # Common patterns in AWS events
   # Currently triggered by GuardDuty. Patterns list supports future event sources.
   patterns = [
      # GuardDuty pattern
      ['detail', 'resource', 'instanceDetails', 'instanceId'],

      # Direct resource pattern
      ['detail', 'resource', 'instanceId'],

      # EC2 state change pattern
      ['detail', 'instance-id'],

      # CloudTrail event pattern
      ['requestParameters', 'instanceSet', 'items', 0, 'instanceId']
   ]

   for pattern in patterns:
      try:
         value = event
         for key in pattern:
            if isinstance(key, int):
               value = value[key]
            else:
               value = value[key]

         if value and isinstance(value, str) and value.startswith('i-'):
            return value
      except (KeyError, IndexError, TypeError):
         continue

   return None


# Lambda Handler
def lambda_handler(event: Dict, context) -> Dict:
   """
   Main Lambda handler for automated EC2 compromise response.

   Args:
      event (dict): The event payload. Expected to contain 'instanceId'.
      context: Lambda execution context.

   Returns:
      dict: Result of the incident response process.
   """

   start_time = time.time()
   executed_actions = [] # Track all actions taken

   # Extract instance ID from event
   instance_id = None
   event_source = "unknown"

   try:
      # 1 Direct invocation with instanceId
      if 'instanceId' in event:
         instance_id = event['instanceId']
         event_source = "direct_invocation"

      # 2 GuardDuty finding format
      elif 'detail' in event and 'resource' in event['detail']:
         event_source = "guardduty"
         resource = event['detail']['resource']

         # Extract from GuardDuty finding structure
         if 'instanceDetails' in resource and 'instanceId' in resource['instanceDetails']:
            instance_id = resource['instanceDetails']['instanceId']

         elif 'resource' in event['detail'] and 'instanceId' in event['detail']['resource']:
            instance_id = event['detail']['resource']['instanceId']

      # 3 Try to find instance ID in various common locations
      if not instance_id:
         # Check common patterns in the event
         instance_id = find_instance_id_in_event(event)

      if not instance_id:
         raise ValueError("No instanceId found in event payload.")
        
      
      log_incident_event(
         message=f"Initiating automated incident response for instance: {instance_id}",
         severity=SeverityLevel.INFO,
         instance_id=instance_id,
         event_source=event.get('source', 'unknown')
      )

   except (KeyError, ValueError) as e:
      log_incident_event(
         message=f"Invalid event structure: {str(e)}. Event: {json.dumps(event)}",
         severity=SeverityLevel.HIGH
      )
      return {"statusCode": 400, "body": "Error: Missing or invalid instanceId."}
   

   # Execute Response Plan

   # Response philosophy:
   #1. Reduce blast radius
   #2. Preserve evidence
   #3. Rely on the Auto Scaling Group to restore service capacity
   
   try:
      # Step 1: Drain from Load Balancer
      deregister_from_elb(instance_id)
      executed_actions.append({'action': 'DeregisterFromELB', 'status': 'SUCCESS', 'severity': SeverityLevel.HIGH})

      # Step 2: Detach drom Auto Scaling group
      detach_from_asg(instance_id)
      executed_actions.append({'action': 'DetachFromASG', 'status': 'SUCCESS', 'severity': SeverityLevel.HIGH})

      # Step 3: Network Quarantine
      vpc_id = get_instance_vpc_id(instance_id)
      quarantine_sg_id = get_quarantine_sg(vpc_id)
      apply_quarantine_sg(instance_id, quarantine_sg_id)
      executed_actions.append({'action': 'ApplyQuarantineSG', 'status': 'SUCCESS', 'severity': SeverityLevel.CRITICAL})

      # Step 4: Forensic Evidence Collection
      snapshots = take_forensic_snapshot(instance_id)
      executed_actions.append({'action': 'CreateSnapshot', 'status': 'SUCCESS', 'severity': SeverityLevel.HIGH, 'snapshots': snapshots})

      # Step 5: Terminate Instance
      terminate_instance(instance_id)
      executed_actions.append({'action': 'TerminateInstance', 'status': 'SUCCESS', 'severity': SeverityLevel.HIGH})

      # Final log
      log_incident_event(
         message=f"Successfully contained and terminated compromised instance {instance_id}. ASG will launch a replacement.",
         severity=SeverityLevel.INFO,
         instance_id=instance_id,
         actions_executed = executed_actions

      )

   except IncidentResponseError as e:
      executed_actions.append({'action': e.action, 'status': 'FAILED', 'severity':e.severity, 'error': e.message})
      log_incident_event(
         message=f"Incident response failed during {e.action}: {e.message}",
         severity=e.severity,
         instance_id=instance_id,
         error_type=e.__class__.__name__
      )

   except Exception as e:
     executed_actions.append({'action': 'UnhandledException', 'status': 'FAILED', 'severity':SeverityLevel.CRITICAL, 'error': str(e)})
     log_incident_event(
         message=f"Unhandled exception during incident response: {str(e)}",
         severity=SeverityLevel.CRITICAL,
         instance_id=instance_id,
         traceback = traceback.format_exc()
      ) 
     
   # Finalize and Report
   duration_ms = round((time.time() - start_time) * 1000, 2)
   emit_cloudwatch_metrics(executed_actions, context)

   return {
      "statusCode": 200,
      "body": {
         "instanceId": instance_id,
         "actions": executed_actions,
         "containmentStatus": "SUCCESS" if all(a['status'] == 'SUCCESS' for a in executed_actions) else "PARTIAL_FAILURE",
         "timestamp": datetime.now(timezone.utc).isoformat(),
         "durationMs": duration_ms,
         "standards": COMPLIANCE_STANDARDS

      }
   }



