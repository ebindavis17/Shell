# Check if data at rest in RDS Instances is encrypted using KMS
# (encrypted is COMPLIANT, Not-encrypted is NON_COMPLIANT)
#
# Trigger Type: Configuration AWS::RDS::DBInstance
# Scope of Changes: AWS::RDS::DBInstance.

import json
import boto3

kms = boto3.client('kms')


def evaluate_compliance(configuration_item):
    # db = configuration_item['configuration']['dBInstanceIdentifier']
    isStorageEnc = configuration_item['configuration']['storageEncrypted']
    kmskey = configuration_item['configuration']['kmsKeyId']

    if isStorageEnc:
        validkmskeys = kms.list_keys()
        for keys in validkmskeys['Keys']:
            if keys['KeyArn'] == kmskey:
                return 'COMPLIANT'
    return 'NON_COMPLIANT'


def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']

    if configuration_item['configurationItemStatus'] == 'ResourceDeleted':
        return

    result_token = 'No token found.'
    if 'resultToken' in event:
        result_token = event['resultToken']

    compliance_type = evaluate_compliance(configuration_item)

    print(compliance_type)

    config = boto3.client('config')

    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType":
                configuration_item["resourceType"],
                    "ComplianceResourceId":
                        configuration_item["resourceId"],
                    "ComplianceType":
                        compliance_type,
                    "Annotation":
                        "Data at rest in RDS Instance is encrypted using KMS",
                    "OrderingTimestamp":
                        configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
