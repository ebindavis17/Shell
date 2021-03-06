import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from OpenSSL import crypto
import pem

config = Config(retries=dict(max_attempts=15))

#Checks the serial number of the External Approved CA's : https://social.connect.abnamro.com/wikis/home?lang=nl-nl#!/wiki/592e98c2-73a5-4e30-8161-927fe9d1faff/page/94137a18-a8d4-43c8-bf6e-3f01dddaa005/version/bec41416-81dd-4c12-a387-52c83d15638f

APPROVED_SER_NUM = [ '00', '2c535eb58f19b58', '7b89d9071eb531b143594ff909bac846', '4daa73ae24a3e0a142090c9ca2b899ec' ,
'56b3d6705c7d44a24b6fcf3b13d4676a' ,'00', '6302cd7c3220f7934a368cbf4b34ba07','1641ab0c9c5b8867', '033af1e6a711a9a0bb2864b11d09fae5' ,
'387dcfde2f8aca6cdd595ddcaa4ee8ea' ,'509' ,'3411dadd551c7849','0098a239', '0098968d' ,'0098968c', '0098a23c',
'066c9fcf99bf8c0a39e2f0788a43e696365bca', '066c9fd29635869f0a0fe58678f85b26bb8a37', '066c9fd5749736663f3b0b9ad9e89e7603f24a' ,
'066c9fd7c1bb104c2943e5717b7b2cc81ac10e']

#for i in APPROVED_SER_NUM :
#   print( i[1:] if i.startswith('0') else i )

acm = boto3.client('acm', config=config)
s3 = boto3.client('s3', config=config)


def get_certificate_authority(certificate_arn):
    response = acm.get_certificate(
        CertificateArn=certificate_arn
    )

    chain = pem.parse(response['CertificateChain'])

    root_certificate = chain[-1]

    return root_certificate.as_text()


def get_certificates():
    paginator = acm.get_paginator('list_certificates')
    response_iterator = paginator.paginate(
        CertificateStatuses=[
            'ISSUED',
        ],
    )

    return [
        get_certificate_authority(certificate['CertificateArn'])
        for response in response_iterator
        for certificate in response['CertificateSummaryList']
    ]


def get_serial_number(certificate):
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
    return certificate.get_serial_number()


def lambda_handler(event, context):
    certificates = get_certificates()

    for certificate in certificates:
        serial_number = get_serial_number(certificate)


#        print('{0:x}'.format(serial_number))
        print('')
        if str('{0:x}'.format(serial_number)) not in APPROVED_SER_NUM:
            print('NON-COMPLIANT', 'Certificate is not from External Approved CA')
        else:
            print('COMPLIANT', 'Certificate is from External Approved CA')


if __name__ == '__main__':
    lambda_handler(
        {'invokingEvent': '{"messageType":"ScheduledNotification"}'}, None)
