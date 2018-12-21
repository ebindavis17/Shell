# Check if password policy requires at least
# one number
#
# (enabled is COMPLIANT, disabled is NON_COMPLIANT)
#
# Trigger Type: Periodic 24 hrs
# Scope of Changes: AWS::::Account

import time
import boto3
from botocore.config import Config

boto3_config = Config(retries={'max_attempts': 10})

iam = boto3.client('iam', config=boto3_config)


def get_account_alias():
    response = iam.list_account_aliases()
    return response['AccountAliases'][0]


def get_account_password_policy():
    try:
        response = iam.get_account_password_policy()
        return response['PasswordPolicy']
    except Exception as e:
        if "cannot be found" in str(e):
            return False


def evaluate_compliance(passwordpolicy):
    if passwordpolicy is False:
        return 'NON_COMPLIANT'
    else:
        if passwordpolicy['RequireNumbers'] is False:
            return 'NON_COMPLIANT'

    return 'COMPLIANT'


def lambda_handler(event, context):
    result_token = 'No token found.'
    if 'resultToken' in event:
        result_token = event['resultToken']

    passwordpolicy = get_account_password_policy()
    compliance_type = evaluate_compliance(passwordpolicy)

    # Print result for easy debugging
    print(compliance_type)

    config = boto3.client('config')
    config.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType':
            "AWS::::Account",
                'ComplianceResourceId':
                    get_account_alias(),
                'ComplianceType':
                    compliance_type,
                'Annotation':
                    'Password policy requires at least one number',
                'OrderingTimestamp':
                    time.time()
        }],
        ResultToken=result_token
    )