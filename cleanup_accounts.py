#!/usr/bin/env python
"""
This script can be used to cleanse a single or multiple accounts of certain or all CFN Stacks. Or just to know the current state.
You can provide an OU and let it walk through them (recursively or not) to find stacks, or you can provide a single account ID.
If you only want to list stacks, just omit the '-rm' option.
You can use a regex pattern ('-s') to search for certain stacks or omit it to list/remove them all.

Note: This script doesn't take StackSets into account. Stacks can of course be re-deployed if they are part of a StackSet.
"""
from __future__ import print_function
from past.builtins import basestring

import boto3
import json
import os
import re
import sys
import time

from argparse import ArgumentParser, ArgumentTypeError
from botocore.exceptions import ClientError, WaiterError
from functools import wraps

# Import libaries from ../lib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lib.organizations as organizations

__version__ = '0.2'

### AWS Organizations constants
ORGANIZATIONS_ACCOUNT = '064670468982'  # aab-billing
ORGANIZATIONS_ROLE = 'cbsp-organizations-account-lifecycle-handler'
# Make use of paths relative to the script's folder
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_DIR = '{}/../../templates/0000-provisioning/target-account-initial-stacks/'.format(SCRIPT_DIR)
CFN_STACK_REGIONS = ['eu-west-1', 'eu-central-1']
# Both error codes are used on different AWS API's, meaning the same
LIMIT_ERRORS = ['LimitExceededException', 'ClientLimitExceededException']
EXCLUDE_ACCOUNTS = ['795384094589', '220254483638']


def exception_handler(original_function, number_of_tries=4, delay=3):
    """
    Provide an exception handler with exponential backoff for AWS API calls
    """
    @wraps(original_function)
    def retried_function(*args, **kwargs):
        for i in range(number_of_tries):
            try:
                return original_function(*args, **kwargs)
            except ClientError as error:
                error_code = error.response['Error']['Code']
                if error_code in LIMIT_ERRORS:
                    backoff = delay * (2**i)
                    time.sleep(backoff)
                ### CFN exception handling:
                elif 'ListStacks' in str(error) and error_code == 'AccessDenied':
                    print('[WARN] Account probably suspended, cannot list stacks by explicit deny')
                    # Return empty list so any subsequent for-loop will not fail
                    return []
                if 'UpdateStack operation: No updates are to be performed' in str(error) and error_code == 'ValidationError':
                    # Stack already up-to-date
                    return original_function(up_to_date=True, *args, **kwargs)
                elif 'UpdateStack' in str(error):
                    print('[ERROR] Stack failed to update in the validation phase')
                    raise
                else:
                    raise
    return retried_function


@exception_handler
def assume_role(account_id, role_name, credentials={}):
    """
    Assume a role and return credentials, optionally by using specified credentials
    """
    print('[INFO] Assuming role "{}" in account {}'.format(role_name, account_id))
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


def get_all_regions():
    client = boto3.client('ec2')
    return [region['RegionName'] for region in client.describe_regions()['Regions']]


def deploy_account_initials(account_id, account_metadata, update=False):
    # Scavenge through files in the template folder for CFN stacks to deploy
    for file in os.listdir(TEMPLATE_DIR):
        filename_segments = file.split('.')
        if (filename_segments[-1] in ['yml', 'yaml', 'json']
        and filename_segments[-2] == 'cfn'):
            cfn_settings = {}
            stackname = 'cbsp-{}'.format(filename_segments[0]) # E.g.: cbsp-initial-parameters
            # template = open(TEMPLATE_DIR + file, 'r')
            # cfn_template = template.read()

            # Read the CFN settings file if it exists
            settings_filename = filename_segments[0] + '.settings.json'
            if os.path.isfile(TEMPLATE_DIR + settings_filename):
                cfn_settings = json.load(open(TEMPLATE_DIR + settings_filename, 'r'))

            # Gather the region(s) to deploy the stack and deploy
            # If Regions not provided or no settings file, assume eu-west-1
            if not cfn_settings.get('Regions') or cfn_settings.get('Regions') == 'ANY':
                stack_regions = ['eu-west-1']
            elif all([i in CFN_STACK_REGIONS for i in cfn_settings.get('Regions')]):
                stack_regions = cfn_settings.get('Regions')
            else:
                print('[ERROR] CFN settings for stack "{}" contain an unsupported/invalid region'.format(stackname))

            # Gather required metadata for stack deployment (if requested in settings file)
            for p in cfn_settings.get('ParametersFromMetadata', []):
                try:
                    cfn_settings.setdefault('Parameters', []).append(
                        {
                            'ParameterKey': p['ParameterKey'],
                            'ParameterValue': account_metadata[p['MetadataKey']]
                        }
                    )
                except KeyError:
                    print('[ERROR] In the process of deploying stack "{}", the key "{}" requested from the settings file cannot be found in account metadata'.format(
                        stackname, p['MetadataKey']
                    ))
                    exit(1)

            print('[INFO] Deploying stack "{}" in {} for account {} with {} settings'.format(
                stackname, stack_regions, account_id, 'imported' if cfn_settings else 'default'))
            if cfn_settings.get('Parameters'):
                print('[DEBUG] CFN stack parameters:\n  {}'.format(json.dumps(cfn_settings['Parameters'])))
            # for region in stack_regions:
            #     deploy_resources(cfn_template, stackname, region, account_credentials, cfn_settings, update)


@exception_handler
def get_s3_resource(credentials):
    return boto3.resource('s3',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])


@exception_handler
def get_buckets(s3):
    bucket_iterator = s3.buckets.all()
    return [b for b in bucket_iterator]


@exception_handler
def delete_bucket_with_contents(bucket, s3):
    print('[INFO] Deleting bucket (incl. contents): {}'.format(bucket.name))
    bucket.objects.all().delete()
    # TODO: Need to iterate over objects to also delete versions
    return bucket.delete()


@exception_handler
def get_directconnect_client(region, credentials):
    return boto3.client('directconnect',
                        region_name=region,
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'])


@exception_handler
def get_directconnect_vifs(client):
    return client.describe_virtual_interfaces().get('virtualInterfaces', [])


@exception_handler
def delete_directconnect_vif(vif, client):
    print('[INFO] Removing VIF {}'.format(vif['virtualInterfaceId']))
    return client.delete_virtual_interface(
        virtualInterfaceId=vif['virtualInterfaceId'])


@exception_handler
def delete_stacks(stack_name, region, credentials):
    client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=region)
    return client.delete_stack(StackName=stack_name)


@exception_handler
def list_stacks(region, credentials):
    client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=region)
    paginator = client.get_paginator('list_stacks')
    response_iterator = paginator.paginate()

    # Create dict if stack is in an exceptional state
    return [
        stack['StackName'] if stack['StackStatus'] in ['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE'] else {stack['StackStatus']: stack['StackName']}
        for response in response_iterator
        for stack in response['StackSummaries']
        if stack['StackStatus'] != 'DELETE_COMPLETE'
    ]


def main(account_id=None, ou_path=None, stack_name_pattern=None, recursive_ou_lookup=False,
         remove=False, remove_failed=False, remove_dc_vifs=False, s3_bucket_pattern=None,
         remove_s3=False, show_ou_tree=False, all_regions=False, non_supported_regions=False):
    # Keep count of all matched/deleted stacks so we can show that in the end
    total_count_of_matching_stacks = 0
    if non_supported_regions:
        regions = [r for r in get_all_regions() if r not in CFN_STACK_REGIONS]
    else:
        regions = CFN_STACK_REGIONS if not all_regions else get_all_regions()

    if ou_path:
        print('[INFO] Finding accounts in OU path "{}" {}'.format(
            ou_path, 'recursively' if recursive_ou_lookup else 'non-recursively'))
        accounts = [i for i in organizations.get_accounts_for_path(ou_path, recursive_ou_lookup) if i not in EXCLUDE_ACCOUNTS]
    elif account_id:
        accounts = [account_id]
    print('[INFO] {} accounts after exclusions:\n  {}'.format(len(accounts), accounts))

    for account in accounts:
        org_acct = [v for v in EXISTING_ACCOUNTS if v.get('Id', '') == account][0]
        if show_ou_tree and org_acct:
            ou_tree = organizations.get_ou_tree_for_child(account)
            print('\n{0} {1} | {2} ({3}, joined: {4}) {0}'.format(3*'=', account, org_acct['Name'], ou_tree, org_acct['JoinedTimestamp']))
        else:
            print('\n{0} {1} | {2} {0} (joined: {3})'.format(3*'=', account, org_acct['Name'], org_acct['JoinedTimestamp']))


        # Get admin credentials for the account
        # When account alias already existed, uses acquired alias status info for the account ID
        try:
            account_credentials = assume_role(
                account_id=account,
                role_name='OrganizationAccountAccessRole',
                credentials=ORGANIZATIONS_CREDENTIALS
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('[WARN] Cannot assume role into account, access denied.')
                continue
            else:
                raise

        if s3_bucket_pattern:
            print('[INFO] Finding S3 buckets with the following pattern: {}'.format(s3_bucket_pattern))
            s3_resource = get_s3_resource(account_credentials)
            buckets = get_buckets(s3_resource)
            if buckets:
                filtered_buckets = [
                    b for b in buckets if re.match(s3_bucket_pattern, b.name)
                ]
                print('  {}'.format('\n  '.join([b.name for b in filtered_buckets])))
                if remove_s3:
                    for bucket in filtered_buckets:
                        print(delete_bucket_with_contents(bucket, s3_resource))

        if stack_name_pattern:
            print('[INFO] Searching for stacks with the following pattern: {}'.format(stack_name_pattern))

        for region in regions:
            if remove_dc_vifs:
                dc_client = get_directconnect_client(region, account_credentials)
                vifs = get_directconnect_vifs(dc_client)
                if vifs:
                    print('[INFO] Deleting VIFs first (resolves VGW dependency when removing VPCs)')
                    undesired_states = ['deleting', 'deleted']
                    vif_deleted = None
                    for vif in vifs:
                        if vif['virtualInterfaceState'] not in undesired_states:
                            delete_directconnect_vif(vif, dc_client)
                            vif_deleted = True
                    if vif_deleted:
                        print('[INFO] Wait a minute for deletion to finish, before removing stacks')
                        time.sleep(60)
                    else:
                        print('[INFO] VIFs were already deleted or in the process of being deleted')

            stacks = list_stacks(region, account_credentials)
            matching_stacks = []

            for stack in stacks:
                if isinstance(stack, basestring):
                    # If needed, filter the stacks according to the stack name regex pattern
                    if stack_name_pattern and re.match(stack_name_pattern, stack):
                        matching_stacks.append(stack)
                    elif not stack_name_pattern:
                        matching_stacks.append(stack)
                # If 'stack' is dict, it's in an exceptional state
                elif isinstance(stack, dict):
                    for k,v in stack.items():
                        if k.endswith('_FAILED'):
                            if not stack_name_pattern or re.match(stack_name_pattern, v):
                                print('[INFO] Stack {} in {} state{}'.format(v, k, ', will be removed' if remove_failed else ''))
                                matching_stacks.append(v)
                                # Remove stack although it didnt match if remove_failed is requested
                                if remove_failed and not remove:
                                    # Add to matched stacks count if it needs to be deleted
                                    total_count_of_matching_stacks += 1
                                    print('    [DEBUG] {}'.format(
                                        delete_stacks(v, region, account_credentials)
                                        )
                                    )
                            elif stack_name_pattern and not re.match(stack_name_pattern, v):
                                print('[WARN] Stack {} in {} state but does not match pattern, needs intervention'.format(v, k))
                        # elif k == 'DELETE_FAILED':
                        #     print('[WARN] Stack {} in {} state, needs intervention'.format(v, k))
                        else:
                            print('[INFO] Stack {} in {} state'.format(v, k))

            if matching_stacks:
                print('-- {}: {} total stacks, {} matching --'.format(region, len(stacks), len(matching_stacks)))
                total_count_of_matching_stacks += len(matching_stacks)
                for stack in matching_stacks:
                    print('  {}'.format(stack))
                    if remove == True:
                        print('    [INFO] Removing now..')
                        print('    [DEBUG] {}'.format(
                            delete_stacks(stack, region, account_credentials)
                            )
                        )
                print('----')
            else:
                print('[INFO] No stacks found in {}'.format(region))

    print('\n{}\n[INFO] Total stacks {}: {}'.format('========',
                                                    'deleted' if remove else 'matched',
                                                    total_count_of_matching_stacks))


def parse_args():
    parser = ArgumentParser(description='Account Cleanup script')
    intake = parser.add_mutually_exclusive_group(required=True)
    regions = parser.add_mutually_exclusive_group(required=False)
    intake.add_argument(
        '-ou', '--organizational-unit-path',
        dest='ou_path',
        help='Organizational Unit ID for which child accounts will be cleaned. By default non-recursively.',
        type=str
    )
    intake.add_argument(
        '-a', '--account-id',
        dest='account_id',
        help='Specific account ID to clean',
        type=str
    )
    parser.add_argument(
        '-s', '--stack-name-pattern',
        dest='stack_name_pattern',
        help='Stack name pattern (regex) to remove',
        type=str
    )
    parser.add_argument(
        '-or', '--recursive-ou-lookup',
        dest='recursive_ou_lookup',
        help='Use recursion to select accounts from child OUs (infinite levels) too, only works with "-ou"',
        action='store_true'
    )
    parser.add_argument(
        '-rm', '--remove',
        dest='remove',
        help='Remove the found stacks (by default only lists them). WARNING: This is very permanent!',
        action='store_true'
    )
    parser.add_argument(
        '-rmf', '--remove-failed',
        dest='remove_failed',
        help='Remove failed stacks. WARNING: This is very permanent!',
        action='store_true'
    )
    parser.add_argument(
        '-rdv', '--remove-dc-vifs',
        dest='remove_dc_vifs',
        help='Remove Direct Connect Virtual Interfaces (before CFN operations), so there is no dependency when deleting Virtual Gateways. WARNING: This is very permanent!',
        action='store_true'
    )
    parser.add_argument(
        '-s3', '--s3-bucket-pattern',
        dest='s3_bucket_pattern',
        help='List or remove S3 buckets including contents with a given prefix (before CFN operations)',
        type=str
    )
    parser.add_argument(
        '-rs3', '--remove-s3',
        dest='remove_s3',
        help='Remove the found S3 Buckets (by default only lists them). WARNING: This is very permanent!',
        action='store_true'
    )
    parser.add_argument(
        '-so', '--show-ou-tree',
        dest='show_ou_tree',
        help='Output OU tree for every account (in the header lines)',
        action='store_true'
    )
    regions.add_argument(
        '-ar', '--all-regions',
        dest='all_regions',
        help='Go through all regions, instead of only the CBSP supported regions',
        action='store_true'
    )
    regions.add_argument(
        '-nsr', '--non-supported-regions',
        dest='non_supported_regions',
        help='List/remove stacks in non-supported regions',
        action='store_true'
    )
    parser.add_argument(
        '-d', '--debug',
        dest='debug',
        help='Output some extra debug information',
        action='store_true'
    )

    if len(sys.argv) == 1:
        parser.print_help()
        exit(2)

    return parser.parse_args()


if __name__ == '__main__':
    # Parse args and create some global constants which require some function calls
    args = parse_args()
    ORGANIZATIONS_CREDENTIALS = assume_role(ORGANIZATIONS_ACCOUNT, ORGANIZATIONS_ROLE)
    organizations = organizations.Organizations(ORGANIZATIONS_CREDENTIALS, silent=True)
    EXISTING_ACCOUNTS = organizations.list_accounts()

    main(account_id=args.account_id,
         ou_path=args.ou_path,
         stack_name_pattern=args.stack_name_pattern,
         recursive_ou_lookup=args.recursive_ou_lookup,
         remove=args.remove,
         remove_failed=args.remove_failed,
         remove_dc_vifs=args.remove_dc_vifs,
         s3_bucket_pattern=args.s3_bucket_pattern,
         remove_s3=args.remove_s3,
         show_ou_tree=args.show_ou_tree,
         all_regions=args.all_regions,
         non_supported_regions=args.non_supported_regions)
