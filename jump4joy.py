import boto3
import os
import configparser

# Get the path to the credentials file
aws_directory = os.path.expanduser("~/.aws")
credentials_path = os.path.join(aws_directory, 'credentials')

# Check if the credentials file exists
if os.path.exists(credentials_path):
    # Read AWS credentials from the file
    config = configparser.ConfigParser()
    config.read(credentials_path)

    aws_access_key_id = config.get('default', 'aws_access_key_id')
    aws_secret_access_key = config.get('default', 'aws_secret_access_key')
    aws_region_name = config.get('default', 'region')

    # Use the credentials
    print("AWS Access Key ID:", aws_access_key_id)
    print("AWS Secret Access Key:", aws_secret_access_key)
    print("AWS Region Name:", aws_region_name)

    # Now you can use these credentials for your Boto3 session
    # For example:
    import boto3
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=aws_region_name
    )

    # Use the session to create clients and resources
    # For example:
    ec2 = session.client('ec2')

    # List all EC2 instances
    response = ec2.describe_instances()
    print(response)

else:
    print("AWS credentials file not found.")