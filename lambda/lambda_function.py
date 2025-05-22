
# Module Imports
import boto3
import json


# Variable Declaration



# Function Definition
def lambda_handler(event, context):

    # Create S3 client to interact with the S3 service
    s3 = boto3.client("s3")

    # Create a list to capture unencrypted object violations
    violations = []

    # Loop through each object upload included in the S3 event trigger
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        try:
            # Get the encryption status of the uploaded object
            response = s3.head_object(Bucket=bucket, Key=key)
            encryption = response.get("ServerSideEncryption", None)

            if not encryption:
                print(f"Unencrypted Upload detected: {bucket}/{key}")
                violations.append({"bucket": bucket, "key": key})

            else:
                print(f"Encrypted upload: {bucket}/{key}")
            
        except Exception as e:
            print(f"Error checking object: {bucket}/{key} - {str(e)}")

    result = {
        "statusCode" : 200,
        "body" : f"Checked {len(event['Records'])} file(s), violations: {violations}" 
 }
    # Log result to CloudWatch
    print(json.dumps(result, indent=2))


    # Log Total Violation
    print(f"Total violations found: {len(violations)}")

    return result