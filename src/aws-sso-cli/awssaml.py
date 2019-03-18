#!/usr/bin/env python3

import sys
import boto3
import configparser
import base64
import xml.etree.ElementTree as ET
from os.path import expanduser

class awssaml:
    def __init__(self, assertion):
        self.assertion = assertion

    def parse(self):
        # Better error handling is required for production use.
        if self.assertion == '':
            #TODO: Insert valid error checking/handling
            print('Response did not contain a valid SAML assertion')
            sys.exit(1)

        # Parse the returned assertion and extract the authorized roles
        awsroles = []
        root = ET.fromstring(base64.b64decode(self.assertion))
        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    awsroles.append(saml2attributevalue.text)
        arns = {}
        arns['role_arn'] = awsroles[0].split(',')[0]
        arns['principal_arn'] = awsroles[0].split(',')[1]
        return arns

    def assume_role(self, role_arn, principal_arn, region):
        # Use the assertion to get an AWS STS token using Assume Role with SAML
        client = boto3.client(
            'sts',
            region_name=region
        )
        token = client.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=self.assertion,
        )
        return token

    def write_credentials_file(self, token, region, output_format = 'json', awsconfigfile = '/.aws/credentials'):
        # Write the AWS STS token into the AWS credential file
        home = expanduser("~")
        filename = home + awsconfigfile

        # Read in the existing config file
        config = configparser.RawConfigParser()
        config.read(filename)

        # Put the credentials into a saml specific section instead of clobbering
        # the default credentials
        if not config.has_section('saml'):
            config.add_section('saml')

        config.set('saml', 'output', output_format)
        config.set('saml', 'region', region)
        config.set('saml', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
        config.set('saml', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
        config.set('saml', 'aws_session_token', token['Credentials']['SessionToken'])

        # Write the updated config file
        with open(filename, 'w+') as configfile:
            config.write(configfile)

        print('\n\rSTS credentials have been stored in the AWS configuration file {0} under the saml profile.'.format(filename))
        print('Note that they will expire at {0}.'.format(token['Credentials']['Expiration']))
        print('To use these credentials, call the AWS CLI with the --profile option. See example below: \n\r')
        print('aws sts get-caller-identity --profile saml \n\r')
