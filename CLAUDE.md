# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains Python scripts to quickly enable AWS security and compliance features across AWS accounts. Many AWS security features are not enabled by default and require manual enablement across multiple regions. These "Fast Fix" scripts automate enabling features like GuardDuty, EBS encryption, S3 block public access, VPC flow logs, etc.

## Dependencies and Setup

Install dependencies using either pipenv or pip:

```bash
# Using pipenv (Python 3.8)
pipenv install

# Using pip
pip install -r requirements.txt
```

Core dependencies: `boto3`, `botocore`, `pytz`

## Architecture and Common Patterns

### Script Structure

Each Fast Fix follows a consistent architecture:

```
script-name/
├── README.md                    # Explains the feature, usage, and AWS API docs
└── script-name.py              # Standalone Python script
```

Each script is completely self-contained with no shared modules or utilities.

### Standard Script Pattern

All scripts follow this pattern:

1. **Argument parsing** via `do_args()` - returns parsed CLI arguments
2. **Logging setup** in `if __name__ == '__main__'` block with configurable levels
3. **Session management** - Creates boto3 session with optional `--profile` support
4. **Region iteration** via `get_regions()` - Returns all regions with us-east-1 first, or single region if `--region` specified
5. **Main logic** in `main(args, logger)` - Iterates regions and performs the fix
6. **Action functions** - Separate functions for enabling/disabling features
7. **Keyboard interrupt handling** - Exits gracefully on Ctrl+C

### Standard CLI Arguments

Every script supports these common arguments:

- `--debug` - Print debugging info (sets logger to DEBUG)
- `--error` - Print error info only (sets logger to ERROR)
- `--timestamp` - Output logs with timestamp and toolname
- `--region REGION` - Only process specified region (instead of all regions)
- `--profile PROFILE` - Use this AWS CLI profile instead of default/env credentials
- `--actually-do-it` - **Required to make changes** (dry-run mode without this flag)

Script-specific arguments vary (e.g., `--accept-invite` for GuardDuty, `--flowlog-bucket` for VPC flow logs).

### Dry-Run Safety Pattern

**CRITICAL:** All scripts default to dry-run mode and require `--actually-do-it` flag to make changes. This prevents accidental modifications. Scripts log what _would_ be done without this flag.

Example:
```python
if args.actually_do_it is True:
    logger.info(f"Enabling feature in {region}")
    enable_feature(client, region)
else:
    logger.info(f"You Need To Enable feature in {region}")
```

### Region Handling

The `get_regions()` function pattern:
- Returns `[args.region]` if `--region` specified
- Otherwise returns all enabled regions from `ec2:DescribeRegions`
- Always returns us-east-1 first (important for global services)
- Some scripts handle disabled regions with try/except ClientError for UnauthorizedOperation

### Error Handling

Scripts use:
- `botocore.exceptions.ClientError` for AWS API errors
- Logging at appropriate levels (ERROR for failures, INFO for actions, DEBUG for status checks)
- Special handling for disabled regions (raises UnauthorizedOperation or specific error codes)
- Boto3 logging is silenced to WARNING level to reduce noise

### Running Scripts

Typical usage pattern:

```bash
# Dry-run (see what would change)
./script-name.py

# Dry-run with debug output
./script-name.py --debug

# Dry-run for specific region
./script-name.py --region us-west-2

# Actually make changes (all regions)
./script-name.py --actually-do-it

# Make changes with specific AWS profile
./script-name.py --profile my-profile --actually-do-it
```

## Notable Implementation Details

### Multi-Region by Default
Most scripts iterate through ALL AWS regions because security features are regional. Scripts call `ec2.describe_regions()` to get the current list of enabled regions, ensuring new regions are automatically included.

### us-east-1 First
The `get_regions()` function always returns us-east-1 first because some AWS features have global components in us-east-1 or special handling for that region.

### Organizations and Delegated Admin
Scripts in `org-delegation/` and `org-configure-alternate-contacts/` must run in the AWS Organizations payer/management account. GuardDuty delegation requires per-region API calls, while other services use the global Organizations API.

### VPC Flow Logs Cross-Region Notes
The vpc-flow-logs script assumes pre-March 2019 regions for cross-region S3 log delivery. Opt-in regions (post-March 2019) require the S3 bucket in the same region as the flow log.

### Recent Additions
The `ebs-block-public-access/` directory is one of the newer Fast Fixes, following the same patterns as older scripts. Some directories may not be listed in the main README.md yet (e.g., `cwl-retention/`).
