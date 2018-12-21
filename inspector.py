

from __future__ import print_function

import boto3
import sys

inspector = boto3.client('inspector')
cw_event = boto3.client('events')

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

class Inspector:

    def __init__(self, credentials, silent=False, debug=False):
        self.silent = silent
        self.debug = debug
        self.client = boto3.client('inspector',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )

    def assessment_targets(self):        
            
        targets = []
        response = inspector.list_assessment_targets()

        for targetarns in response['assessmentTargetArns']:
            targets.append(targetarns)

        for arns in targets:
            response = client.describe_assessment_targets(
                assessmentTargetArns=[
                arns ]
            )

            for name in response['assessmentTargets']:
                if name['name'] == 'cbsp-assessment-target':
                    print('Account has assessment targets "cbsp-assessment-target". Hence step 1 succeeded')
                    arn = name['arn']            

            templates = []
            response = client.list_assessment_templates()

            for access_templates in response['assessmentTemplateArns']:
                templates.append(access_templates)

            for template in templates:
                response = client.describe_assessment_templates(
                    assessmentTemplateArns=[
                    template
                    ]
                )
                for target in response['assessmentTemplates']:
                    if  arn in target['assessmentTargetArn']:
                        print('Account has assessment template with "cbsp-assessment-target" as target name. Hence Step 2 succeeded')
                        return cbsp_assessment_target

    # def get_rule():

    #         event_rules = []
    #         evaluation = self.assessment_templates()
    #         print(evaluation)

    #         response = cw_event.list_rules()

    #         for rules in response['Rules']:
    #             event_rules.append(rules['Name'])

    #         for rule in event_rules:
    #             if rule.startswith('StackSet-cbsp-inspector-'):
    #                 print('CW event rule {} is present in the account. Hence Step 3 succeeded'.format(rule))

if __name__ == '__main__':
   ORGANIZATIONS_CREDENTIALS = assume_role(ORGANIZATIONS_ACCOUNT, ORGANIZATIONS_ROLE)
   organizations = organizations.Organizations(ORGANIZATIONS_CREDENTIALS, debug=True)
   aab_ou_id = organizations.find_ou_id(AAB_OU_PATH)
   all_aab_accounts = organizations.get_child_accounts(aab_ou_id, recursive=True, inactive=False)

