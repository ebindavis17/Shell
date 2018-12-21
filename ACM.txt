from OpenSSL import crypto
import pem
import time
import json
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

APPROVED_SERIAL_NUMBERS = [
    '2c535eb58f19b58',
    '7b89d9071eb531b143594ff909bac846',
    '4daa73ae24a3e0a142090c9ca2b899ec',
    '56b3d6705c7d44a24b6fcf3b13d4676a',
    '6302cd7c3220f7934a368cbf4b34ba07',
    '1641ab0c9c5b8867',
    '33af1e6a711a9a0bb2864b11d09fae5',
    '387dcfde2f8aca6cdd595ddcaa4ee8ea',
    '509',
    '3411dadd551c7849',
    '98a239',
    '98968d',
    '98968c',
    '98a23c',
    '66c9fcf99bf8c0a39e2f0788a43e696365bca',
    '66c9fd29635869f0a0fe58678f85b26bb8a37',
    '66c9fd5749736663f3b0b9ad9e89e7603f24a',
    '66c9fd7c1bb104c2943e5717b7b2cc81ac10e',

    # This certificate is signed by 509
    '48982de2a92cb339e1c8f933358275d3e4f88255',

    # This certificate is signed by 33af1e6a711a9a0bb2864b11d09fae5
    'c8ee0c90d6a89158804061ee241f9af',
]

boto3_config = Config(retries={'max_attempts':15})


def get_root_certificate(acm, certificate_arn):
    response = acm.get_certificate(
        CertificateArn=certificate_arn
    )

    chain = pem.parse(response['CertificateChain'])

    root_certificate = chain[-1]

    return crypto.load_certificate(crypto.FILETYPE_PEM, root_certificate.as_text())


def evaluate_compliance(acm, certificate):
    domain_name = certificate['DomainName']
    root_certificate = get_root_certificate(acm, certificate['CertificateArn'])

    serial_number = '{0:x}'.format(root_certificate.get_serial_number())
    issuer = root_certificate.get_issuer().CN

    if serial_number in APPROVED_SERIAL_NUMBERS:
        return 'COMPLIANT', 'Certificate [{}] with root CA [{}] is approved'.format(domain_name, issuer)

    return 'NON_COMPLIANT', 'Certificate [{}] with root CA [{}] is NOT approved'.format(domain_name, issuer)


def get_evaluation(acm, certificate):
    compliance_type, annotation = evaluate_compliance(acm, certificate)

    return {
        'ComplianceResourceType': 'AWS::ACM::Certificate',
        'ComplianceResourceId': certificate['CertificateArn'],
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': time.time()
    }



def get_evaluations_for_region(region):

    acm = boto3.client('acm', region_name=region, config=boto3_config)

    paginator = acm.get_paginator('list_certificates')
    response_iterator = paginator.paginate(
        CertificateStatuses=[
            'ISSUED',
        ],
    )

    return [
        get_evaluation(acm, certificate)
        for response in response_iterator
        for certificate in response['CertificateSummaryList']
    ]

def get_evaluations():
    regions = boto3.session.Session().get_available_regions('acm')

    return [
        evaluation
        for region in regions
        for evaluation in get_evaluations_for_region(region)
    ]

def lambda_handler(event, context):
    evaluations = get_evaluations()

    if 'resultToken' in event:
        result_token = event['resultToken']

        chunks = (evaluations[x:x + 100]
                  for x in xrange(0, len(evaluations), 100))

        config = boto3.client('config')
        for chunk in chunks:
            config.put_evaluations(
                Evaluations=chunk,
                ResultToken=result_token
            )
    else:
        print(json.dumps(evaluations, indent=2, sort_keys=True))


if __name__ == '__main__':
    lambda_handler(
        {'invokingEvent': '{"messageType":"ScheduledNotification"}'}, None)
