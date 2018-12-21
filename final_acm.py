import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from OpenSSL import crypto
import pem

config = Config(retries=dict(max_attempts=15))

#Checks the serial number of the External Approved CA's : https://social.connect.abnamro.com/wikis/home?lang=nl-nl#!/wiki/592e98c2-73a5-4e30-8161-927fe9d1faff/page/94137a18-a8d4-43c8-bf6e-3f01dddaa005/version/bec41416-81dd-4c12-a387-52c83d15638f


# /CN=ABN AMRO Bank Infra CA G2/OU=ABN AMRO CISO/O=ABN AMRO Bank N.V./L=Amsterdam/C=NL
# 199625043413670744
# 2c535eb58f19b58

# /C=BM/O=QuoVadis Limited/CN=QuoVadis Root CA 2
# 414441045951046581292119350263127430575186018901
# 48982de2a92cb339e1c8f933358275d3e4f88255

# /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root G2
# 16692601292094917965351216382751144367
# c8ee0c90d6a89158804061ee241f9af


APPROVED_SER_NUM = [
    '03 3a f1 e6 a7 11 a9 a0 bb 28 64 b1 1d 09 fa e5',
    '05 09',
    '34 11 da dd 55 1c 78 49',
]

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
#    return certificate.get_serial_number()
def get_issuer(certificate):
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
    return certificate.get_issuer()


def lambda_handler(event, context):
    certificates = get_certificates()

    for certificate in certificates:
        serial_number = get_serial_number(certificate)
#        issuer = get_issuer(certificate)

#        print(issuer)

#        print(serial_number)
        res = ('{0:x}'.format(serial_number))
        print(res)
#        print('')

#        if str(serial_number) not in APPROVED_SER_NUM:
 #           print('NON-COMPLIANT', 'Certificate is not from External Approved CA')
  #      else:
   #         print('COMPLIANT', 'Certificate is from External Approved CA')


if __name__ == '__main__':
    lambda_handler(
        {'invokingEvent': '{"messageType":"ScheduledNotification"}'}, None)