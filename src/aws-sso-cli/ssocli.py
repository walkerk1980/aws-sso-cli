#!/usr/bin/env python3

from io import StringIO
import json
import argparse
import getpass
import os
import requests
import boto3
from awssaml import awssaml
from awssso import awssso
from awsexceptions import AuthCodeError
from awsexceptions import AccessTokenError
from awsexceptions import GetSAMLAssertionError

#TODO 
# switch from argparse to Click and prompt for required values
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--appinstanceid', nargs='?', const='NO', help='Application instance id. Every AWS account or custom SAML application has a specific id in AWS SSO')
parser.add_argument('-r', '--rolename', nargs='?', const='NO', help='Role name. Actually it is the name of a profile but for practical terms it is the role you will assume')
parser.add_argument('-v', '--verbose', nargs='?', const='NO', help='Verbose mode. For even more information or debugging uncomment the variables\' values throughout the script')
parser.add_argument('-u', '--directoryurl', nargs='?', const='NO', default='d-example.awsapps.com', help='The URL of your SSO Directory')
parser.add_argument('-d', '--dirname', nargs='?', const='NO', default='d-example', help='The Name of your SSO Directory')
parser.add_argument('-n', '--netbios', nargs='?', const='NO', default='d-example', help='The NETBIOS Name of your SSO Directory')
parser.add_argument('-l', '--login', nargs='?', const='NO', default='user1@example.com', help='The Active Directory UserName for Login to SSO Directory')
parser.add_argument('-s', '--stsregion', nargs='?', const='NO', default='us-west-2', help='The Region to generate AWS STS credentials for and set as config file default')
parser.add_argument('-S', '--ssoregion', nargs='?', const='NO', default='us-east-1', help='The Region where your SSO Directory resides')
parser.add_argument('-p', '--password', nargs='?', const='NO', help='The Active Directory Password to Login to SSO Directory with User specified by -l')
args = parser.parse_args()

print('\n\rDirectory URL: ' + args.directoryurl)
print('Directory Name: ' + args.dirname)
print('NETBIOS Name: ' + args.netbios)
print('SSO Region: ' + args.ssoregion)
print('STS Region: ' + args.stsregion + '\n\r')

if not args.password:
    try:
        args.password = getpass.getpass('Please type password for user ' + args.login + ': ')
    except Exception as e:
        print(e)
        exit(1)

if args.verbose:
    print('\n\rStep 1: Get Authentication Code using the AD user credentials')
    print('-------')
    print('   - Getting Authentication Code from ' + args.directoryurl + '...\n\r')

sso = awssso(args.netbios, args.dirname, args.directoryurl, args.ssoregion, args.login, args.password, args.verbose)

try:
    authcode_values = sso.get_authentication_code()
except AuthCodeError as e:
    print(e)
    exit(1)
except Exception:
    raise

if args.verbose:
    print('\n\rStep 2: Get Access Token using the Authentication Code')
    print('-------')
    print('   - Exchanging Authentication code for Access Token...\n\r')

try:
    token_response = sso.get_access_token(authcode_values['authcode'],authcode_values['referer'],authcode_values['cookies'])
except AccessTokenError as e:
    print(e)
    exit(1)
except Exception:
    raise

# If an Access Token is successfully obtained then it will be used to list the applications configured in AWS SSO for this user.
# If appinstanceid and rolename args are not passed then it will show the list of sso applications
# The the user copy the application instance id and pass it as an argument to this module.

if not args.appinstanceid and not args.rolename:
    if args.verbose:
        print('Step 3: Use the Access Token to get the list of applications configured in AWS SSO')
        print('-------')

    instances = sso.list_application_instances(token_response['token'],token_response['cookies'])
    print('\n\r   - Listing application instances for user ' + args.login + ':\n\r')
    for instance in instances['result']:
        print('Id: ' + instance['id'],)
        print('Name: ' + instance['name'])
        print('Description: ' + instance['description'] + '\n\r')
    if args.verbose:
        print('\n\rTo get a list of the roles that you can assume in each AWS account,')
        print('copy the application instance id of the AWS account and pass it as argument. For example:\n\r')
        print('\n\r./ssocli.py -i ins-1becf2edf4961234')
        print('\n\rRun ./ssocli.py -h for more information about how to use this module\n\r')

# If only the application instance id is passed as argument then list the roles associated to the application instance (aws account).
elif args.appinstanceid and not args.rolename:
    if args.verbose:
        print('Step 3: Use the Access Token to get the list of profiles (roles) assigned to the AWS account')
        print('-------')

    roles = sso.list_roles_for_appinstanceid(args.appinstanceid, token_response['cookies'])
    print('\n\r   - Listing profiles (roles) available for the application instance ' + args.appinstanceid + '\n\r')
    for role in roles['result']:
        print('Name: ' + role['name'] + '\n\r')

    if args.verbose:
        print('\n\rTo assume any of the roles listed above, pass it\'s Name as argument')
        print('along with the application instance id of the AWS account. For example:\n\r')
        print('./ssocli.py -id ins-1becf2edf4961234 -r ViewOnlyAcces\n\r')
        print('Run ./ssocli.py -h for more information about how to use this module\n\r')
    exit(0)

# If both the application instance id and the role name are passed as arguments
# then get the SAML assertion and call STS AssumeRoleWithSAML
elif args.appinstanceid and args.rolename:
    if args.verbose:
        print('\n\rStep 3: Get SAML assertion for the application by using the Access Token')
        print('--------')
        print('   - Getting the SAML endpoint for the application instance ' + args.appinstanceid + '...\n\r')

    encoded_saml = sso.get_saml_assertion(args.appinstanceid, args.rolename, token_response['cookies'])

    if args.verbose:
        print('\n\rStep 4: Get AWS Credentials using the SAML assertion\n\r')
        print('--------')
        print('\n\r   - Calling parsesaml.py to extract the role and saml provider from response.saml and pass them to AssumeRoleWithSAML\n\r')
    
    saml = awssaml(encoded_saml)
    saml_attributes=saml.parse()
    token = saml.assume_role(saml_attributes['role_arn'], saml_attributes['principal_arn'], args.stsregion)
    saml.write_credentials_file(token, args.stsregion)

    sts = boto3.Session(profile_name='saml').client('sts')
    who_am_i = json.dumps(sts.get_caller_identity()['Arn'])
    print('\n\rAssumedRoleIdentity: ' + who_am_i + '\n\r')
        
