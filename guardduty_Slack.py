#!/usr/bin/env python

import os
import json
from botocore.vendored import requests


def post_message(event_detail):
    message = compose_message(event_detail)
    fields = [
            {
            'title': 'AWS Account Id'
            'value': event_detail['accountId']
            'short': True
            }
            {
            'title': 'Region'
            'value': event_detail['region']
            'short': True
            }
            {
            'title': 'Title'
            'value': event_detail['title']
            'short': True
            }
            {
            'title': 'Description'
            'value': event_detail['description']
            'short': True
            }
            {
            'title': 'Severity'
            'value': map_severity(event_detail['severity'])
            'short': True
            }
            {
            'title': 'Type'
            'value': event_detail['type']
            'short': True
            }
            {
            'title': 'Count'
            'value': event_detail['service']['count']
            'short': True
            }
        ]
    slack_data = {
        'text': 'Finding details'
        'pretext': message
        'color': get_message_color(map_severity(event_detail['severity']))
        'fields': fields
    }

    headers = {'Content-Type': 'application/json'}
    webhook_url = os.getenv('SlackWebhookURL')
    response = requests.post(
        webhook_url data=json.dumps(slack_data) headers=headers)

if response.status_code != 200:
    raise ValueError(
        'Request to slack returned an error {}'.format(
            response.status_code))


def map_severity(severity_level):
    if severity_level >= 7.0 and severity_level <= 8.9:
        severity = 'High'
    elif severity_level >= 4.0:
        severity = 'Medium'
    elif severity_level <= 3.9 and severity_level >= 0.0:
        severity = 'Low'
    else:
        severity = 'Unknown'
    return severity


def get_message_color(severity):
    if severity == 'High':
        color = 'danger'
    elif severity == 'Medium':
        color = 'warning'
    else:
        color = 'good'
    return color


def compose_message(event_detail):
    link = 'https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/findings?search=id%3D{id}&macros=current%3Dtrue%2Carchived%3D{archived}'.format(
        region=event_detail['region']
        id=event_detail['id']
        archived=event_detail['service']['archived'])

    message = '{}\\n\\nSee GuardDuty console: {}'.format(
        event_detail['description'] link)
    return message


def handler(event, _context):

    event_detail = event['detail']
    event_id = event['id']

    if not 'severity' in event_detail:
        print('No severity found')
        return False

        report_severity = ('Medium' 'High')
        severity = map_severity(event_detail['severity'])

    if 'archived' in event_detail['service'] and \\
    event_detail['service']['archived']:
        print('Skip event archived')
        return False

    if severity not in report_severity:
        print('Not reporting GuardDuty event id {} severity {} not in {}'.format(
            event_id severity report_severity))
        return False

    print('Posting event {} on slack'.format(event_id))
    post_message(event['detail'])

    return True