
import boto3
import json
from common import Account
from datetime import datetime


class PlatformComplianceReport:

    platorm_rules = [
        'IAM_001', 'IAM_002', 'IAM_003', 'IAM_004', 'IAM_005', 'IAM_006', 'IAM_007', 'IAM_008', 'IAM_009', 'IAM_010',
        'IAM_011', 'IAM_012', 'IAM_013', 'IAM_014', 'IAM_015', 'IAM_016', 'IAM_017', 'IAM_018', 'IAM_019', 'IAM_020',
        'CT_001', 'CT_005', 'CT_006', 'CT_007', 'CT_008', 'CT_009', 'CT_010',
        'VPC_003', 'VPC_004', 'VPC_005', 'VPC_006', 'VPC_007',
        'CW_002', 'CW_003', 'CW_004', 'CW_005', 'CW_006', 'CW_007', 'CW_008', 'CW_009', 'CW_010',
        'KMS_002', 'CONF_001', 'GUARDDUTY_001', 'GUARDDUTY_002', 'SHIELD_003',
    ]

    def __init__(self, account):
        self.account = account

    def get_resource_id(self, compliance_result):
        return compliance_result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']

    def get_resource_type(self, compliance_result):
        return compliance_result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']

    def get_compliance_type(self, compliance_result):
        return compliance_result['ComplianceType']

    def get_evaluation_timestamp(self, compliance_result):
        return compliance_result['ResultRecordedTime'].strftime('%d/%m/%Y %H:%M:%S')

    def get_compliance_results(self, rule):
        client = self.account.get_client('config')
        paginator = client.get_paginator('get_compliance_details_by_config_rule')
        response_iterator = paginator.paginate(
            ConfigRuleName=rule,
            Limit=100,
        )

        return [
            evaluation_result
            for response in response_iterator
            for evaluation_result in response['EvaluationResults']
        ]

    def get_results(self):
        return [
            {
                'evaluation_time': self.get_evaluation_timestamp(compliance_result),
                'resource_type': self.get_resource_type(compliance_result),
                'resource_id': self.get_resource_id(compliance_result),
                'rule_name': rule,
                'compliance_type': self.get_compliance_type(compliance_result),
            }
            for rule in self.platorm_rules
            for compliance_result in self.get_compliance_results(rule)
        ]


if __name__ == '__main__':
    account = Account()

    s3_client = account.get_client('s3')

    report = PlatformComplianceReport(account)
    results = report.get_results()

    now = datetime.now()
    report_time = now.strftime('%d/%m/%Y %H:%M:%S')

    results = [
        {
            'report_time': report_time,
            'account_id': account.id,
            'account_alias': account.alias,
            'region': account.region,
            'evaluation_time': result['evaluation_time'],
            'resource_type': result['resource_type'],
            'resource_id': result['resource_id'],
            'rule_name': result['rule_name'],
            'compliance_type': result['compliance_type'],
        }
        for result in results
    ]

    print('Writing report for %s to logging bucket' % account.id)

    key = 'platform-compliance/{account_id}/{region}/{year}/{month}/{day}/report-{suffix}.json'.format(
        account_id=account.id,
        region=account.region,
        year=now.year,
        month=now.month,
        day=now.day,
        suffix=now.strftime('%H%M%S')
    )
    s3_client.put_object(
        GrantRead='id="e9535778c0acb3c857c159b3a011b763262abfad6769fe8f3386471a7befd3d1", id="219ad23f1414517c4ff242fa83475b9760a6770b0301973a95acfca63ffbcf81"',
        Body=json.dumps(results),
        Bucket='aab-compliance-reports',
        Key=key,
        ServerSideEncryption='AES256',
    )


