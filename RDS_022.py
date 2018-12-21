# Check if RDS Instances are tagged as per the tagging policy..
# Report if Block ID-tag and Billing code-tag are not present or doesn't have values.
# (enabled is COMPLIANT, disabled is NON_COMPLIANT)
#
# Trigger Type: Configuration AWS::RDS::DBInstance and Periodic 24 hrs.
# Scope of Changes: AWS::RDS::DBInstance.

import json
import boto3

APPLICABLE_RESOURCES = ['AWS::RDS::DBInstance']
REQUIRED_TAG_KEYS = ['Block ID', 'Billing code','OAR/OPR ID','Business Application CI','Environment','Confidentiality','Integrity','Availability']

def check_tags(tags):

    for key in REQUIRED_TAG_KEYS:
        if key not in tags or not tags[key]:
            return False
    return True

def evaluate_compliance(configuration_item):
    if configuration_item['resourceType'] not in APPLICABLE_RESOURCES:
        return {
            'compliance_type': 'NOT_APPLICABLE',
            'annotation': 'The rule doesn\'t apply to resources of type ' +
            configuration_item['resourceType'] + '.'
        }

    if configuration_item['configurationItemStatus'] == 'ResourceDeleted':
        return {
            'compliance_type': 'NOT_APPLICABLE',
            'annotation': 'The configurationItem was deleted and therefore cannot be validated.'
        }

    current_tags = configuration_item['tags']
    compliant = check_tags(current_tags)

    if compliant:
        return {
            'compliance_type': 'COMPLIANT',
            'annotation': 'Block ID and Billing code are set'
        }
    else:
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': 'Block ID or Billing code are not set'
        }


def lambda_handler(event, _context):
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']

    result_token = 'No token found.'
    if 'resultToken' in event:
        result_token = event['resultToken']

    evaluation = evaluate_compliance(configuration_item)

    config = boto3.client('config')
    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType':
                    configuration_item['resourceType'],
                'ComplianceResourceId':
                    configuration_item['resourceId'],
                'ComplianceType':
                    evaluation['compliance_type'],
                'Annotation':
                    evaluation['annotation'],
                'OrderingTimestamp':
                    configuration_item['configurationItemCaptureTime']
            },
        ],
        ResultToken=result_token
    )
