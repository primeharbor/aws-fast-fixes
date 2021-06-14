# IAM

This script will update the password policy in your account to an industry accepted baseline based on commercial media company usage.
John Olivers New

## Why?

*[IAM Password Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html) can set a custom password policy on your AWS account to specify complexity requirements and mandatory rotation periods for your IAM users' passwords. If you don't set a custom password policy, IAM user passwords must meet the default AWS password policy.

## What the script does.

This script updates the iam account password policy to an industry accepted baseline based on commercial media company usage.

If --auto is specified the scripts default settings will be applied there is no further policy input needed from the user.


**Note:** HardExpiry and AllowUsersToChangePassword should be enabled with care as they would require an admin to reset or recreate the user.


## Usage

```bash
usage: change_password-policy.py [-h] [--debug] [--error] [--timestamp]
                           [--region REGION] [--profile PROFILE]
                           [--actually-do-it] [--accept-invite MASTERID]

optional arguments:
  -h, --help            show this help message and exit
  --profile  PROFILENAME            
                        Use this CLI profile (instead of default or env credentials)
  --auto                Use default 'strong' password policy stance
  --debug               Display debug logging messages
  --Dry_Run             Executes the call to the AWS IAM api otherwise will default to a 'Dry Run Operation'
  --MinimumPasswordLength  MINLENGTH
                        Specify Password minimum lengh using Number(default: 10)
  --RequireSymbols      True | False
                        Specify Password Policy use of requiring symbols(True or False), Default: True

  --RequireUppercaseCharacters  True | False
                        Specify Password Policy use of requiring Upper Case Characters(True or False), Default: True

  --RequireLowercaseCharacters  True | False
                        Specify Password Policy use of requiring Lower Case Characters(True or False), Default: True

  --AllowUsersToChangePassword  True | False
                        Specify Password Policy to allow users to change their own password(True or False), Default: True
  --MaxPasswordAge  PASSWORDAGEASNUM
                        Specify Password maximum age using Number, default: 365
  --PasswordReusePrevention  PASSWORDREUSELIMITASNUM
                        Specify Password Policy Reuse prevention as the number of previous passwords to store and prevent the user from using. Recieves Number., Default: 12

  --HardExpiry          True | False
                        Specify Password Policy require admin privileges to reset a users password(True or False), Default: False
```

You must specify `--actually-do-it` for the changes to be made. Otherwise the script runs in dry-run mode only.


## AWS Docs

* [IAM Password Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html)
* [Boto3 IAM](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.update_account_password_policy)

