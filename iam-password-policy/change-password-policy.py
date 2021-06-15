#!/usr/bin/env python3

from copy import Error
import boto3
from botocore.exceptions import ClientError
import os
import logging
from botocore.session import Session





def main(args, logger):
    '''Executes the Primary Logic of the Fast Fix'''

    # If they specify a profile use it. Otherwise do the normal thing
    if args.profile:
        session = boto3.Session(profile_name=args.profile)
    else:
        session = boto3.Session()

    try:
        response = setPasswordPolicy(args, client= session.client(service_name='iam'))
        logging.debug("Response:"+str(response))
        logging.info("Response: Successfuly updated password policy")
    except Error as err:
        logging.error("Authentication Failed, Network Connectivity is an issue, or Something else went wrong. Use --debug for more information.")
        logging.debug("error:"+str(err))
        logging.debug()


def setPasswordPolicy( args ,client= None,):
    #Excute account password policy change
    Dry_Run= True
    if not args.Dry_Run:
        Dry_Run= False
    
    strong_stance = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "MaxPasswordAge": 180,
        "PasswordReusePrevention": 15,
        "HardExpiry": False }

    if args.auto:
        response = client.update_account_password_policy(
        MinimumPasswordLength=strong_stance["MinimumPasswordLength"],
        RequireSymbols=strong_stance["RequireSymbols"],
        RequireNumbers=strong_stance["RequireNumbers"],
        RequireUppercaseCharacters=strong_stance["RequireUppercaseCharacters"],
        RequireLowercaseCharacters=strong_stance["RequireLowercaseCharacters"],
        AllowUsersToChangePassword=strong_stance["AllowUsersToChangePassword"],
        MaxPasswordAge=strong_stance["MaxPasswordAge"],
        PasswordReusePrevention=strong_stance["PasswordReusePrevention"],
        HardExpiry=strong_stance["HardExpiry"],
        DryRun=Dry_Run)

    else:
        response = client.update_account_password_policy(
        MinimumPasswordLength=args.MinimumPasswordLength,
        RequireSymbols=args.RequireSymbols,
        RequireNumbers=args.RequireNumbers,
        RequireUppercaseCharacters=args.RequireUppercaseCharacters,
        RequireLowercaseCharacters=args.RequireLowercaseCharacters,
        AllowUsersToChangePassword=args.AllowUsersToChangePassword,
        MaxPasswordAge= args.MaxPasswordAge,
        PasswordReusePrevention=args.PasswordReusePrevention,
        HardExpiry=args.HardExpiry,
        DryRun=Dry_Run)

   
    
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return(True)
    else:
        return(False)
        

def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", help="Use this CLI profile (instead of default or env credentials)")
    parser.add_argument("--auto", help="Use default 'strong' password policy stance")
    parser.add_argument("--debug", help="Display debug logging messages")
    parser.add_argument("--Dry_Run", help="Executes the call to the AWS IAM api otherwise will default to a 'Dry Run Operation'", action='store_true')
    parser.add_argument("--MinimumPasswordLength", help="Specify Password minimum lengh using Number(default: 14)", default=14)
    parser.add_argument("--RequireSymbols", help="Specify Password Policy use of requiring symbols(True or False), Default: True", default= True)
    parser.add_argument("--RequireUppercaseCharacters", help="Specify Password Policy use of requiring Upper Case Characters(True or False), Default: True" , default= True)
    parser.add_argument("--RequireLowercaseCharacters", help="Specify Password Policy use of requiring Lower Case Characters(True or False), Default: True", default= True)
    parser.add_argument("--AllowUsersToChangePassword", help="Specify Password Policy to allow users to change their own password(True or False), Default: True", default= True)
    parser.add_argument("--MaxPasswordAge", help="Specify Password maximum age using Number, default: 180", default=180)
    parser.add_argument("--PasswordReusePrevention", help="Specify Password Policy Reuse prevention as the number of previous passwords to store and prevent the user from using. Recieves Number., Default: 12", default=12)
    parser.add_argument("--HardExpiry", help="Specify Password Policy require admin privileges to reset a users password(True or False), Default: False", default=False)

    
    args = parser.parse_args()

    return(args)


#main
if __name__ == '__main__':

    args = do_args()
    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    logger = logging.getLogger('enable-iam-password-policy')
    
    # Silence Boto3 & Friends
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    try:
        main(args, logger)
    except KeyboardInterrupt:
        exit(1)