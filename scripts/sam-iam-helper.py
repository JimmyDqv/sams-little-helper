#!/usr/bin/env python3

import sys
from os.path import expanduser
from time import sleep
import argparse
import configparser
import datetime
import dateutil
import json
import boto3

# Constants
DEFAULT_SESSION_DURATION = 3600
DEFAULT_PROFILE_NAME = 'sams_helper'
IAM_ROLE_AND_POLICY_PREFIX = 'sams_helper'
CREATED_BY_TAG_VALUE = 'sam_iam_helper'

# Global Boto3 Client
iam_client = boto3.client('iam')


# Get the IAM config for each Lambda in a CloudFormation stack
def list_lambda_functions_iam_config(stackname: str) -> str:
    lambda_function_names = get_lambda_functions(stackname)
    lambda_functions = []
    for lambda_function in lambda_function_names:
        function_iam_config = {}
        lambda_config = get_lambda_function_conf(lambda_function)
        function_iam_config['LambdaConfig'] = lambda_config

        iam_role_name = lambda_config['Role'].split('/')[-1]
        role = get_iam_role_info(iam_role_name)
        function_iam_config['IAM'] = role

        function_iam_config['IAM']['RolePolicies'] = get_inline_policy_docs(
            iam_role_name)

        function_iam_config['IAM']['RoleManagedPolicies'] = get_attached_policy_config(
            iam_role_name)

        lambda_functions.append(function_iam_config)

    return lambda_functions


# Get all Lambda functions in a CloudFormation stack
def get_lambda_functions(stackname: str) -> list:
    cloudformation_client = boto3.client('cloudformation')
    lambda_functions = []

    stack_resources = cloudformation_client.list_stack_resources(
        StackName=stackname
    )
    for resource in stack_resources['StackResourceSummaries']:
        if(resource['ResourceType'] == 'AWS::Lambda::Function'):
            lambda_functions.append(resource['PhysicalResourceId'])

    return lambda_functions


# Get information about a Lambda function
def get_lambda_function_conf(function_name: str) -> dict:
    lambda_client = boto3.client('lambda')
    lambda_config = lambda_client.get_function_configuration(
        FunctionName=function_name
    )
    lambda_config.pop('ResponseMetadata', None)

    return lambda_config


# Get info about an IAM Role
def get_iam_role_info(iam_role_name: str) -> str:
    role = iam_client.get_role(
        RoleName=iam_role_name
    )
    role.pop('ResponseMetadata', None)
    return role


# Get policy documents for inline IAM policies for an IAM role
def get_inline_policy_docs(iam_role_name: str) -> str:
    inline_policy_docs = []

    role_inline_policies = iam_client.list_role_policies(
        RoleName=iam_role_name,
        MaxItems=99
    )

    for policy_name in role_inline_policies['PolicyNames']:
        inline_policy_doc = iam_client.get_role_policy(
            RoleName=iam_role_name,
            PolicyName=policy_name
        )
        inline_policy_doc.pop('ResponseMetadata', None)
        inline_policy_docs.append(inline_policy_doc)

    return inline_policy_docs


# Get attached policies for an IAM Role
def get_attached_policy_config(iam_role_name: str) -> str:
    attached_policy_configs = []

    role_attached_policies = iam_client.list_attached_role_policies(
        RoleName=iam_role_name,
        MaxItems=99
    )

    for attached_policy in role_attached_policies['AttachedPolicies']:
        attached_policy_conf = iam_client.get_policy(
            PolicyArn=attached_policy['PolicyArn']
        )
        attached_policy_conf.pop('ResponseMetadata', None)
        attached_policy_configs.append(attached_policy_conf)

    return attached_policy_configs


# Get the name for a cloned IAM role for an Lambda function
def get_role_clone_name(lambda_function_iam_config):
    sams_helper_role_name = f"{IAM_ROLE_AND_POLICY_PREFIX}_{lambda_function_iam_config['IAM']['Role']['RoleName']}"
    sams_helper_role_name = sams_helper_role_name[:64] if len(
        sams_helper_role_name) > 64 else sams_helper_role_name
    return sams_helper_role_name


# Creates an cloned IAM role for a Lambda function
def create_iam_role_clone(lambda_function_iam_config: dict) -> str:
    sams_helper_role_name = get_role_clone_name(lambda_function_iam_config)
    print(f"Create a role named {sams_helper_role_name}")

    role_trust = lambda_function_iam_config['IAM']['Role']['AssumeRolePolicyDocument']
    role_trust['Statement'].append({
        "Effect": "Allow",
        "Principal": {
            "AWS": f"arn:aws:iam::{boto3.client('sts').get_caller_identity().get('Account')}:root"
        },
        "Action": "sts:AssumeRole"
    })

    if does_role_exists(sams_helper_role_name):
        delete_role(sams_helper_role_name)

    create_role(sams_helper_role_name, lambda_function_iam_config['IAM']['Role']['Path'],
                role_trust, f"SAMs Helper copy of role {lambda_function_iam_config['IAM']['Role']['Arn']}")

    attach_managed_policies(
        sams_helper_role_name, lambda_function_iam_config['IAM']['RoleManagedPolicies'])

    put_inline_policies(sams_helper_role_name,
                        lambda_function_iam_config['IAM']['RolePolicies'])

    return sams_helper_role_name


# Get the ARN of an IAM role if it exists
def get_role_arn(role_name: str) -> str:
    try:
        role = iam_client.get_role(
            RoleName=role_name
        )
        return role['Role']['Arn']
    except Exception:
        return None


# Check if an IAM role exists
def does_role_exists(role_name: str) -> str:
    try:
        iam_client.get_role(
            RoleName=role_name
        )
        return True
    except Exception:
        return False


# Delete an IAM role
def delete_role(role_name: str):
    attached_policies = get_attached_policy_config(role_name)
    for attached_policy in attached_policies:
        iam_client.detach_role_policy(
            RoleName=role_name,
            PolicyArn=attached_policy['Policy']['Arn']
        )

    inline_policies = get_inline_policy_docs(role_name)
    for inline_policy in inline_policies:
        iam_client.delete_role_policy(
            RoleName=role_name,
            PolicyName=inline_policy['PolicyName']
        )

    iam_client.delete_role(
        RoleName=role_name
    )


# Creates an IAM role
def create_role(role_name: str, path: str, trust_document: dict, description: str):
    iam_client.create_role(
        Path=path,
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_document),
        Description=description,
        MaxSessionDuration=3600,
        Tags=[
            {
                'Key': 'CreatedBy',
                'Value': CREATED_BY_TAG_VALUE
            },
        ]
    )


# Attach AWS managed IAM policies to an IAM role
def attach_managed_policies(role_name: str, policies: list):
    for managed_policy in policies:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=managed_policy['Policy']['Arn']
        )


# Puts inline IAM policies to an IAM role
def put_inline_policies(role_name: str, policies: list):
    for inline_policy in policies:
        policy_name = f"{IAM_ROLE_AND_POLICY_PREFIX}_{inline_policy['PolicyName']}"
        policy_name = policy_name[:64] if len(
            policy_name) > 64 else policy_name

        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(inline_policy['PolicyDocument'])
        )


# Get the Config object for a Lambda function
def get_function_config(lambda_function_name: str) -> dict:
    function_configs = list_lambda_functions_iam_config(args.stackname)
    for function_config in function_configs:
        function_name = function_config['LambdaConfig']['FunctionName']
        if function_name == args.functionname:
            return function_config


######################################################################
######## Helper Functions ############################################
######################################################################

# Get the path to the users aws cli credentials file
def get_credentials_file() -> str:
    home = expanduser("~")
    config_file = f"{home}/.aws/credentials"

    return config_file


# Parse datetime to a string with format yyyy-mm-dd hh:mm:ss
def parse_time(date_time: datetime) -> str:
    date_time = date_time.astimezone(dateutil.tz.tzlocal())
    return date_time.strftime('%Y-%m-%d %H:%M:%S')


# Datetime to string converter that can be used by json to parse datetime
def my_date_time_converter(o) -> str:
    if isinstance(o, datetime.datetime):
        return o.__str__()


# Print the IAM session credentials to console
def print_credentials(credentials: dict):
    print(f"AWS_ACCESS_KEY_ID={credentials['AccessKeyId']}")
    print(f"AWS_SECRET_ACCESS_KEY={credentials['SecretAccessKey']}")
    print(f"AWS_SESSION_TOKEN={credentials['SessionToken']}")


# Store the IAM session credentials to a named profile
def store_credentials(credentials: dict, profile: str, credentials_file: str):
    config = configparser.ConfigParser()
    config.read(credentials_file)

    config.remove_section(profile)
    config.add_section(profile)
    config.set(profile, 'aws_access_key_id', credentials['AccessKeyId'])
    config.set(profile, 'aws_secret_access_key',
               credentials['SecretAccessKey'])
    config.set(profile, 'aws_session_token', credentials['SessionToken'])

    with open(credentials_file, "w+") as out:
        config.write(out)


# Call STS to assume a role
def sts_assume_role(arn: str, duration: int) -> dict:
    sts_client = boto3.client('sts')
    kwargs = {'RoleArn': arn}
    kwargs['RoleSessionName'] = 'sams_helper_session'
    kwargs['DurationSeconds'] = duration

    return sts_client.assume_role(**kwargs)

######################################################################
######## Main Entry Points ###########################################
######################################################################


# Function mapped to list command.
# Will list all Lambda functions and roles in an CloudFormation stack
def list_functions(args: dict):
    function_configs = list_lambda_functions_iam_config(args.stackname)
    for function_config in function_configs:
        function_name = function_config['LambdaConfig']['FunctionName']
        role_name = function_config['LambdaConfig']['Role'].split("/")[-1]
        print(f"Function: {function_name}, Role: {role_name}")


# Function mapped to create command.
# Will create a SAM local cloned IAM role
def create_sam_role(args: dict):
    function_config = get_function_config(args.functionname)
    role_name = create_iam_role_clone(function_config)
    print(f"Role '{role_name}' created")


# Function mapped to assume command.
# Will assume the SAM local cloned IAM role mapping to a Lambda function.
# If the SAM local cloned IAM role doesn't exists it will be created first
def assume_sam_role(args: dict):
    function_config = get_function_config(args.functionname)
    sams_helper_role_name = get_role_clone_name(function_config)

    if args.duration:
        session_duration = int(args.duration)
    else:
        session_duration = DEFAULT_SESSION_DURATION

    if args.profile:
        profile = args.profile
    else:
        profile = DEFAULT_PROFILE_NAME

    if not does_role_exists(sams_helper_role_name):
        sams_helper_role_name = create_iam_role_clone(function_config)

    sams_helper_role_name_arn = get_role_arn(sams_helper_role_name)
    print(f"assume a role arn {sams_helper_role_name_arn}")

    try:
        assumed_role = sts_assume_role(
            sams_helper_role_name_arn, session_duration)
    except Exception:
        # Assuming a newly created role might fail. Sleep and retry!
        sleep(10)
        assumed_role = sts_assume_role(
            sams_helper_role_name_arn, session_duration)

    store_credentials(assumed_role['Credentials'],
                      profile, get_credentials_file())

    print(
        f"Role Assumed, credentials expire: {parse_time(assumed_role['Credentials']['Expiration'])}")


if __name__ == '__main__':

    if len(sys.argv) == 1:
        print('You must supply a command!')
        sys.exit()

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    # List command
    parser_list = subparsers.add_parser(
        'list', help='List all Lambda functions and roles in a stack')
    parser_list.add_argument(
        '--stackname', required=True, help='The name of the CloudFormation stack to read from')
    parser_list.add_argument(
        '--region', required=False, help='The AWS region for resources, overrides the default region in AWS profile')
    parser_list.set_defaults(func=list_functions)

    # Create Role command
    parser_create = subparsers.add_parser(
        'create', help='Create a SAM Local clone of the IAM Role for a Lambda Function')
    parser_create.add_argument(
        '--stackname', required=True, help='The name of the CloudFormation stack to read from')
    parser_create.add_argument(
        '--functionname', required=True, help='The name of the Lambda function to create a sam local role for')
    parser_create.add_argument(
        '--region', required=False, help='The AWS region for resources, overrides the default region in AWS profile')
    parser_create.set_defaults(func=create_sam_role)

    # Assume Role command
    parser_assume = subparsers.add_parser(
        'assume', help='Assume the SAM Local clone of the IAM Role for a Lambda Function')
    parser_assume.add_argument(
        '--stackname', required=True, help='The name of the CloudFormation stack to read from')
    parser_assume.add_argument(
        '--functionname', required=True, help='The name of the Lambda function to create a sam local role for')
    parser_assume.add_argument(
        '--region', required=False, help='The AWS region for resources, overrides the default region in AWS profile')
    parser_assume.add_argument(
        '--duration', required=False, help='Duration the temporary credentials in seconds, default 3600')
    parser_assume.add_argument(
        '--profile', required=False, help='Name of the AWS CLI profile to store credentials in, default sams_helper')
    parser_assume.set_defaults(func=assume_sam_role)

    # Call the functions
    args = parser.parse_args()
    if args.region:
        boto3.setup_default_session(region_name=args.region)

    try:
        args.func(args)
    except Exception as e:
        print("Command failed!")
        print(e)
