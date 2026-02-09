#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError
import logging
import json


def main(args, logger):
    '''Executes the Primary Logic of the Fast Fix'''

    # If they specify a profile use it. Otherwise do the normal thing
    if args.profile:
        session = boto3.Session(profile_name=args.profile)
    else:
        session = boto3.Session()

    # Create IAM role if needed (global resource, only do once)
    iam_role_arn = ensure_iam_role_exists(session, args, logger)
    if iam_role_arn is None:
        logger.error("Failed to ensure IAM role exists. Cannot proceed.")
        return

    # Get all the Regions for this account
    for region in get_regions(session, args):
        try:
            process_region(session, region, args, logger, iam_role_arn)
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                logger.error(f"Failed to process region {region}. Denied by SCP?")
            elif e.response['Error']['Code'] == 'AccessDeniedException':
                logger.warning(f"Access denied in region {region}. Bedrock may not be available in this region.")
            else:
                logger.error(f"Error processing region {region}: {e}")


def process_region(session, region, args, logger, iam_role_arn):
    '''Process a single region'''
    logger.debug(f"Processing region {region}")

    bedrock_client = session.client("bedrock", region_name=region)
    logs_client = session.client("logs", region_name=region)

    # Create region-specific bucket name
    bucket_name = f"{args.bucket_name_prefix}-{region}"

    # Ensure S3 bucket exists in this region
    if not ensure_s3_bucket_exists(session, args, bucket_name, region, logger):
        logger.error(f"Failed to ensure S3 bucket {bucket_name} exists in {region}")
        return

    # Ensure log group exists in this region
    if not ensure_log_group_exists(logs_client, args, region, logger):
        logger.error(f"Failed to ensure log group exists in {region}")
        return

    # Get current logging configuration
    try:
        current_config = bedrock_client.get_model_invocation_logging_configuration()
        logging_config = current_config.get('loggingConfig', {})
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging_config = {}
        else:
            raise

    # Build desired configuration
    desired_config = build_logging_config(args, iam_role_arn, bucket_name, region)

    # Check if configuration needs to be updated
    if needs_update(logging_config, desired_config, logger):
        if args.actually_do_it:
            logger.info(f"Configuring Bedrock model invocation logging in {region}")
            configure_bedrock_logging(bedrock_client, desired_config, region, logger)
        else:
            logger.info(f"Would configure Bedrock model invocation logging in {region}")
    else:
        logger.debug(f"Bedrock logging already configured correctly in {region}")


def build_logging_config(args, iam_role_arn, bucket_name, region):
    '''Build the desired logging configuration'''
    config = {
        'cloudWatchConfig': {
            'logGroupName': args.log_group_name,
            'roleArn': iam_role_arn,
            'largeDataDeliveryS3Config': {
                'bucketName': bucket_name,
                'keyPrefix': f'bedrock-large-data/{region}/'
            }
        },
        's3Config': {
            'bucketName': bucket_name,
            'keyPrefix': f'bedrock-logs/{region}/'
        },
        'textDataDeliveryEnabled': not args.disable_text,
        'imageDataDeliveryEnabled': not args.disable_image,
        'embeddingDataDeliveryEnabled': not args.disable_embedding,
        'videoDataDeliveryEnabled': not args.disable_video,
        # 'audioDataDeliveryEnabled': not args.disable_audio
    }
    return config


def needs_update(current_config, desired_config, logger):
    '''Check if the current configuration needs to be updated'''
    if not current_config:
        return True

    # Check each key in desired config
    for key, value in desired_config.items():
        if key not in current_config:
            logger.debug(f"Configuration needs update: missing key {key}")
            return True
        if isinstance(value, dict):
            # For nested dicts, do a deep comparison
            if current_config[key] != value:
                logger.debug(f"Configuration needs update: {key} differs")
                return True
        else:
            if current_config[key] != value:
                logger.debug(f"Configuration needs update: {key} = {current_config[key]} vs {value}")
                return True

    return False


def configure_bedrock_logging(bedrock_client, config, region, logger):
    '''Configure Bedrock model invocation logging'''
    try:
        response = bedrock_client.put_model_invocation_logging_configuration(
            loggingConfig=config
        )
        logger.info(f"Successfully configured Bedrock logging in {region}")
        return True
    except ClientError as e:
        logger.error(f"Failed to configure Bedrock logging in {region}: {e}")
        return False


def ensure_log_group_exists(logs_client, args, region, logger):
    '''Ensure CloudWatch Logs log group exists'''
    try:
        # Check if log group exists
        response = logs_client.describe_log_groups(
            logGroupNamePrefix=args.log_group_name,
            limit=1
        )

        for log_group in response.get('logGroups', []):
            if log_group['logGroupName'] == args.log_group_name:
                logger.debug(f"Log group {args.log_group_name} already exists in {region}")
                return True

        # Log group doesn't exist, create it
        if args.actually_do_it:
            logger.info(f"Creating log group {args.log_group_name} in {region}")
            logs_client.create_log_group(logGroupName=args.log_group_name)
            return True
        else:
            logger.info(f"Would create log group {args.log_group_name} in {region}")
            return True

    except ClientError as e:
        logger.error(f"Error ensuring log group exists in {region}: {e}")
        return False


def ensure_s3_bucket_exists(session, args, bucket_name, region, logger):
    '''Ensure S3 bucket exists in the specified region'''
    s3_client = session.client('s3', region_name=region)

    try:
        # Check if bucket exists
        s3_client.head_bucket(Bucket=bucket_name)
        logger.debug(f"S3 bucket {bucket_name} already exists")

        # Set bucket policy even if bucket already exists to ensure it's correct
        if args.actually_do_it:
            set_bucket_policy_for_bedrock(s3_client, bucket_name, logger)

        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            # Bucket doesn't exist, create it
            if args.actually_do_it:
                logger.info(f"Creating S3 bucket {bucket_name} in {region}")
                try:
                    if region == 'us-east-1':
                        s3_client.create_bucket(Bucket=bucket_name)
                    else:
                        s3_client.create_bucket(
                            Bucket=bucket_name,
                            CreateBucketConfiguration={'LocationConstraint': region}
                        )

                    # Enable versioning (recommended for logging buckets)
                    s3_client.put_bucket_versioning(
                        Bucket=bucket_name,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )

                    # Set bucket policy to allow Bedrock to write logs
                    set_bucket_policy_for_bedrock(s3_client, bucket_name, logger)

                    logger.info(f"Successfully created S3 bucket {bucket_name}")
                    return True
                except ClientError as e:
                    logger.error(f"Failed to create S3 bucket: {e}")
                    return False
            else:
                logger.info(f"Would create S3 bucket {bucket_name} in {region}")
                return True
        elif error_code == '403':
            logger.error(f"Access denied to bucket {bucket_name}. Bucket may exist in another account.")
            return False
        else:
            logger.error(f"Error checking bucket {bucket_name}: {e}")
            return False


def set_bucket_policy_for_bedrock(s3_client, bucket_name, logger):
    '''Set bucket policy to allow Bedrock logging service to write'''
    # Get the current account ID
    sts_client = s3_client._client_config.__dict__.get('_user_provided_options', {}).get('credentials')
    # Use a separate STS client to get account ID
    import boto3
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()['Account']

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSLogDeliveryWrite",
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id
                    }
                }
            },
            {
                "Sid": "AWSLogDeliveryAclCheck",
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock.amazonaws.com"
                },
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id
                    }
                }
            }
        ]
    }

    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(policy)
        )
        logger.debug(f"Set bucket policy for Bedrock logging on {bucket_name}")
    except ClientError as e:
        logger.warning(f"Failed to set bucket policy: {e}")


def ensure_iam_role_exists(session, args, logger):
    '''Ensure IAM role exists with appropriate permissions'''
    iam_client = session.client('iam')

    try:
        # Check if role exists
        response = iam_client.get_role(RoleName=args.iam_role_name)
        logger.debug(f"IAM role {args.iam_role_name} already exists")
        return response['Role']['Arn']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            # Role doesn't exist, create it
            if args.actually_do_it:
                logger.info(f"Creating IAM role {args.iam_role_name}")
                return create_iam_role(iam_client, args, logger)
            else:
                logger.info(f"Would create IAM role {args.iam_role_name}")
                # Return a placeholder ARN for dry-run mode
                sts_client = session.client('sts')
                account_id = sts_client.get_caller_identity()['Account']
                return f"arn:aws:iam::{account_id}:role/{args.iam_role_name}"
        else:
            logger.error(f"Error checking IAM role: {e}")
            return None


def create_iam_role(iam_client, args, logger):
    '''Create IAM role with trust policy and permissions for Bedrock logging'''

    # Trust policy for Bedrock
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        # Create the role
        response = iam_client.create_role(
            RoleName=args.iam_role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Role for Amazon Bedrock model invocation logging'
        )
        role_arn = response['Role']['Arn']
        logger.info(f"Created IAM role {args.iam_role_name}")

        # Create and attach inline policy for CloudWatch Logs and S3
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    "Resource": f"arn:aws:logs:*:*:log-group:{args.log_group_name}:*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject"
                    ],
                    "Resource": f"arn:aws:s3:::{args.bucket_name_prefix}-*/*"
                }
            ]
        }

        iam_client.put_role_policy(
            RoleName=args.iam_role_name,
            PolicyName='BedrockLoggingPolicy',
            PolicyDocument=json.dumps(policy_document)
        )
        logger.info(f"Attached logging policy to role {args.iam_role_name}")

        return role_arn

    except ClientError as e:
        logger.error(f"Failed to create IAM role: {e}")
        return None


def get_regions(session, args):
    '''Return a list of regions with us-east-1 first. If --region was specified, return a list with just that'''

    # If we specified a region on the CLI, return a list of just that
    if args.region:
        return [args.region]

    # otherwise return all the regions, us-east-1 first
    ec2 = session.client('ec2', region_name="us-east-1")
    response = ec2.describe_regions()
    output = ['us-east-1']
    for r in response['Regions']:
        # return us-east-1 first, but don't return it twice
        if r['RegionName'] == "us-east-1":
            continue
        output.append(r['RegionName'])
    return output


def do_args():
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--timestamp", help="Output log with timestamp and toolname", action='store_true')
    parser.add_argument("--region", help="Only Process Specified Region")
    parser.add_argument("--profile", help="Use this CLI profile (instead of default or env credentials)")
    parser.add_argument("--actually-do-it", help="Actually Perform the action", action='store_true')

    # Bedrock logging specific arguments
    parser.add_argument("--log-group-name", required=True, help="CloudWatch Logs log group name for Bedrock logging")
    parser.add_argument("--bucket-name-prefix", required=True, help="S3 bucket name prefix for Bedrock logging (bucket will be created as {prefix}-{region} in each region)")
    parser.add_argument("--iam-role-name", required=True, help="IAM role name for Bedrock logging (role will be created if it doesn't exist)")

    # Data type delivery flags
    parser.add_argument("--disable-text", help="Disable text data delivery", action='store_true')
    parser.add_argument("--disable-image", help="Disable image data delivery", action='store_true')
    parser.add_argument("--disable-embedding", help="Disable embedding data delivery", action='store_true')
    parser.add_argument("--disable-video", help="Disable video data delivery", action='store_true')
    parser.add_argument("--disable-audio", help="Disable audio data delivery", action='store_true')

    args = parser.parse_args()

    return args


if __name__ == '__main__':

    args = do_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    logger = logging.getLogger('enable-bedrock-logging')
    ch = logging.StreamHandler()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.error:
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)

    # Silence Boto3 & Friends
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    # create formatter
    if args.timestamp:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        formatter = logging.Formatter('%(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    try:
        main(args, logger)
    except KeyboardInterrupt:
        exit(1)
