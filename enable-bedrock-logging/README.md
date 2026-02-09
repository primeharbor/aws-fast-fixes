# Enable Bedrock Model Invocation Logging

This script will enable model invocation logging for Amazon Bedrock in all regions in your account.

## Why?

Amazon Bedrock model invocation logging allows you to capture detailed information about model invocations, including prompts, responses, and metadata. This is critical for:
- Security and compliance auditing
- Monitoring and troubleshooting model usage
- Cost analysis and optimization
- Content moderation and safety monitoring

## What the script does

This script iterates through all regions returned by `ec2:DescribeRegions` and configures Bedrock model invocation logging to deliver logs to both CloudWatch Logs and S3. The script:

1. Creates the IAM role (if it doesn't exist) with appropriate trust policy and permissions
2. Creates the S3 bucket (if it doesn't exist) in the specified region
3. Creates the CloudWatch Logs log group (if it doesn't exist) in each region
4. Configures Bedrock model invocation logging with the specified settings

The script is idempotent - it will only create resources if they don't exist, and only update logging configuration if settings have changed.

## Usage

```bash
usage: enable-bedrock-logging.py [-h] [--debug] [--error] [--timestamp]
                                  [--region REGION] [--profile PROFILE]
                                  [--actually-do-it]
                                  --log-group-name LOG_GROUP_NAME
                                  --bucket-name BUCKET_NAME
                                  [--bucket-region BUCKET_REGION]
                                  --iam-role-name IAM_ROLE_NAME
                                  [--disable-text]
                                  [--disable-image]
                                  [--disable-embedding]
                                  [--disable-video]
                                  [--disable-audio]

options:
  -h, --help            show this help message and exit
  --debug               print debugging info
  --error               print error info only
  --timestamp           Output log with timestamp and toolname
  --region REGION       Only Process Specified Region
  --profile PROFILE     Use this CLI profile (instead of default or env credentials)
  --actually-do-it      Actually Perform the action
  --log-group-name LOG_GROUP_NAME
                        CloudWatch Logs log group name for Bedrock logging
  --bucket-name BUCKET_NAME
                        S3 bucket name for Bedrock logging
  --bucket-region BUCKET_REGION
                        S3 bucket region (defaults to AWS_DEFAULT_REGION or AWS_REGION env var)
  --iam-role-name IAM_ROLE_NAME
                        IAM role name for Bedrock logging (role will be created if it doesn't exist)
  --disable-text        Disable text data delivery
  --disable-image       Disable image data delivery
  --disable-embedding   Disable embedding data delivery
  --disable-video       Disable video data delivery
```

You must specify `--actually-do-it` for the changes to be made. Otherwise the script runs in dry-run mode only.

### Example

```bash
# Dry-run to see what would be configured
./enable-bedrock-logging.py \
  --log-group-name /aws/bedrock/modelinvocations \
  --bucket-name my-bedrock-logs \
  --bucket-region us-east-1 \
  --iam-role-name BedrockLoggingRole

# Actually configure logging (all regions, all data types enabled)
./enable-bedrock-logging.py \
  --log-group-name /aws/bedrock/modelinvocations \
  --bucket-name my-bedrock-logs \
  --bucket-region us-east-1 \
  --iam-role-name BedrockLoggingRole \
  --actually-do-it

# Configure with some data types disabled
./enable-bedrock-logging.py \
  --log-group-name /aws/bedrock/modelinvocations \
  --bucket-name my-bedrock-logs \
  --iam-role-name BedrockLoggingRole \
  --disable-image \
  --disable-video \
  --actually-do-it
```

## AWS Docs

* [Amazon Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)
* [PutModelInvocationLoggingConfiguration API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_PutModelInvocationLoggingConfiguration.html)
* [GetModelInvocationLoggingConfiguration API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetModelInvocationLoggingConfiguration.html)
* [boto3 put_model_invocation_logging_configuration()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock/client/put_model_invocation_logging_configuration.html)
* [boto3 get_model_invocation_logging_configuration()](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock/client/get_model_invocation_logging_configuration.html)
