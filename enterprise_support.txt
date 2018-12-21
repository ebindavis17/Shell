#!/usr/bin/env python
"""
Requests Enterprise Support for all accounts beneath the ABN Amro OU (which dont have it yet)
"""

from __future__ import print_function

import boto3
import sys

from botocore.exceptions import ClientError

# Import libaries from ../lib
from os import path
sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import lib.organizations as organizations


### AWS Organizations constants
ORGANIZATIONS_ACCOUNT = '064670468982'  # aab-billing
ORGANIZATIONS_ROLE = 'cbsp-organizations-account-lifecycle-handler'
AAB_OU_PATH = 'ABN Amro'


def assume_role(account_id, role_name, credentials={}):
    """
    Assume a role and return credentials, optionally by using specified credentials
    """
    # print('[INFO] Assuming role "{}" in account {}'.format(role_name, account_id))
    sts_client = boto3.client('sts',
                              aws_access_key_id=credentials.get('AccessKeyId'),
                              aws_secret_access_key=credentials.get('SecretAccessKey'),
                              aws_session_token=credentials.get('SessionToken'),
    )
    role_arn = 'arn:aws:iam::{}:role/{}'.format(account_id, role_name)

    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AccountCreationSession')

    return assumed_role_object['Credentials']


class Support:

    def __init__(self, credentials, silent=False, debug=False):
        self.silent = silent
        self.debug = debug
        self.client = boto3.client('support',
            region_name='us-east-1',  # Support API only lives in us-east-1
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )

    def has_enterprise_support(self):
        try:
            self.client.describe_severity_levels(language='en')
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'SubscriptionRequiredException':
                return False
            elif error_code == 'OptInRequired':
                return 'not_ready'
            elif error_code == 'AccessDeniedException':
                return 'access_denied'
            else:
                raise e
        # Return True if no exception triggered
        return True

    def create_case(self, case):
        return self.client.create_case(
            subject=case['subject'],
            serviceCode=case['serviceCode'],
            severityCode=case['severityCode'],
            categoryCode=case['categoryCode'],
            communicationBody=case['communicationBody'],
            language='en',
            issueType=case.get('issueType', 'technical'),
        ).get('caseId')


if __name__ == '__main__':
    # Parse args and create some global constants which require some function calls
    # args = parse_args()
    ORGANIZATIONS_CREDENTIALS = assume_role(ORGANIZATIONS_ACCOUNT, ORGANIZATIONS_ROLE)
    organizations = organizations.Organizations(ORGANIZATIONS_CREDENTIALS, debug=True)
    aab_ou_id = organizations.find_ou_id(AAB_OU_PATH)
    all_aab_accounts = organizations.get_child_accounts(aab_ou_id, recursive=True, inactive=False)

    no_premium_support_accounts = []
    premium_support_accounts = []
    print('')
    for acct_id in all_aab_accounts:
        print('=== {} ==='.format(acct_id))
        # Get admin credentials for the account
        try:
            account_credentials = assume_role(
                account_id=acct_id,
                role_name='OrganizationAccountAccessRole',
                credentials=ORGANIZATIONS_CREDENTIALS
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('[WARN] Cannot assume role into account, access denied.')
                print('[DEBUG] OU tree of account: {}'.format(
                    organizations.get_ou_tree_for_child(acct_id)))
                continue
            else:
                raise

        ent_support = Support(account_credentials).has_enterprise_support()

        if ent_support:
            premium_support_accounts.append(acct_id)
        if not ent_support:
            print('[INFO] Account has no premium support')
            no_premium_support_accounts.append(acct_id)
        elif ent_support == 'access_denied':
            print('[DEBUG] OU tree of account: {}'.format(
                organizations.get_ou_tree_for_child(acct_id)))

    print('[INFO] Total of {} having premium support, {} have not'.format(
        len(premium_support_accounts), len(no_premium_support_accounts)))

    if no_premium_support_accounts >= 1:
        # Request Enterprise Support AWS Support case for all (active) accounts without it
        enterprise_support_req = {
                'subject': 'Add accounts to ABN Amro Bank Enterprise Support',
                'serviceCode': 'customer-account',
                'categoryCode': 'other-account-issues',
                'severityCode': 'low',
                'communicationBody': 'Hi Support, please add these accounts to Enterprise Support:\n{}'.format(
                    '\n'.join(no_premium_support_accounts)
                )
            }

        # # Create case in Billing account
        print('[INFO] Requesting Enterprise support for {} accounts:\n{}'.format(len(no_premium_support_accounts), no_premium_support_accounts))
        case = Support(ORGANIZATIONS_CREDENTIALS).create_case(enterprise_support_req)
        print('[INFO] "{}" submitted, case ID: {}'.format(enterprise_support_req['subject'], case))
