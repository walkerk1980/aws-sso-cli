#!/usr/bin/env python3

from io import StringIO
import json
import requests
import boto3
from awsexceptions import AuthCodeError
from awsexceptions import AccessTokenError
from awsexceptions import GetSAMLAssertionError

class awssso:
    # CONSTANTS
    # Strings and GWT-RPC objects that need to be passed
    CLIENT_ID = '3bec6266d4c83882'
    GWTPERMUTATION = '72CB37F2131C24A860A9833EB1832775'
    CFDISTURL = 'https://d32i4gd7pg4909.cloudfront.net/d4a64633fc550d3b73b374cc1fa5e8229d4ca51e/WarpDriveLogin/'
    FIXEDSTRING = '3848C107E2AD28077897B8F9CEA6E94D'

    def __init__(self, netbios, dirname, directoryurl, ssoregion, login, password, verbose=None, debug=None):
        self.headers = {}
        self.headers['Content-Type'] = 'text/x-gwt-rpc; charset=utf-8'
        self.headers['X-GWT-Permutation'] = awssso.GWTPERMUTATION
        self.headers['X-GWT-Module-Base'] = awssso.CFDISTURL
        self.netbios = netbios
        self.dirname = dirname
        self.directoryurl = directoryurl
        self.login = login
        self.sso_region = ssoregion
        self.assertion = ''
        self.password = password
        self.verbose = verbose
        self.debug = debug
        self.data = '7|0|11|' + awssso.CFDISTURL + '|' + awssso.FIXEDSTRING + '|com.amazonaws.warpdrive.console.client.GalaxyInternalGWTService|authenticateUser|com.amazonaws.warpdrive.console.shared.LoginRequest_v4/3859384737||' + awssso.CLIENT_ID + '|' + self.netbios + '|' + self.dirname + '|' + self.password + '|' + self.login + '|1|2|3|4|1|5|5|6|6|7|8|0|9|10|6|11|'
        self.authcode_url = 'https://' + self.directoryurl + '/login/WarpDriveLogin/GalaxyInternalService'

    def get_authentication_code(self):
        # Parameters as passed in the http POST request
        referer = 'https://' + self.directoryurl + '/login/?client_id=' + awssso.CLIENT_ID +  '&redirect_uri=https://portal.sso.' + self.sso_region + '.amazonaws.com/auth/wd&organization=' + self.dirname
        self.headers['referer'] = referer

        try:
            AUTHCODE_response = requests.post(self.authcode_url, data=self.data, headers=self.headers)
            if AUTHCODE_response.status_code != 200:
                print('Error status code: ' + str(AUTHCODE_response.status_code))
                raise AuthCodeError('Error retreiving authcode..')
            if '//OK' in AUTHCODE_response.text:
                jsontext = json.load(StringIO(AUTHCODE_response.text[4:]))
                AUTHCODE = jsontext[8][1]
            else:
                print(AUTHCODE_response.text)
                raise AuthCodeError('Error retreiving Authentication Code..')

            if self.verbose:
                print('Authcode: ' + AUTHCODE)

            authcode_return_values = {}
            authcode_return_values['referer'] = referer
            authcode_return_values['authcode'] = AUTHCODE
            authcode_return_values['cookies'] = AUTHCODE_response.cookies
            return authcode_return_values
        except AuthCodeError:
            raise
        except Exception:
            raise

    def get_access_token(self, authcode, referer, cookies):
        if self.verbose:    
            print('\n\rStep 2: Get Access Token using the Authentication Code')
            print('-------')
            print('   - Exchanging Authentication code for Access Token...\n\r')

        headers = {}
        headers['referer'] = referer
        # Note: the csrf_token below can be anything but it has to be present in the request
        token_url = 'https://portal.sso.' + self.sso_region + '.amazonaws.com/auth/wd?auth_code=' + authcode + '&organization=' + self.dirname + '&region=' + self.sso_region + '&wdc_csrf_token=a'

        try:
            TOKEN_response = requests.get(
                token_url,
                cookies=cookies,
                headers=headers,
            )
            if not 'x-amz-sso_authn' in TOKEN_response.request._cookies.keys():
                raise AccessTokenError('Error retreiving Access Token..')
            TOKEN = TOKEN_response.request._cookies['x-amz-sso_authn']
            if self.verbose or self.debug:
                print('\n\rTOKEN: ' + TOKEN + '\n\r')
            access_token_values = {}
            access_token_values['token'] = TOKEN
            access_token_values['cookies'] = TOKEN_response.request._cookies
            return access_token_values
        except AccessTokenError:
            raise
        except Exception:
            raise

    def list_application_instances(self, token, cookies):
        application_instances_response = requests.get(
            'https://portal.sso.' + self.sso_region + '.amazonaws.com/instance/appinstances',
            cookies=cookies,
        )
        instances = json.loads(application_instances_response.text)
        return instances

    def list_roles_for_appinstanceid(self, application_instance_id, cookies):
        roles_response = application_instances_response = requests.get(
            'https://portal.sso.' + self.sso_region + '.amazonaws.com/instance/appinstance/' + application_instance_id + '/profiles',
            cookies=cookies,
        )
        roles = json.loads(roles_response.text)
        return roles

    # If both the application instance id and the role name are passed as argument then get the SAML assertion and call STS AssumeRoleWithSAML
    def get_saml_assertion(self, app_instance_id, role_name, cookies):
        if self.verbose or self.debug:
            print('\n\rStep 3: Get SAML assertion for the application by using the Access Token')
            print('--------')
            print('   - Getting the SAML endpoint for the application instance ' + app_instance_id + '...\n\r')

        #Get the SAML endpoint for the specific SAML application instance (this returns the URL where this module will get the SAML assertion)
        SAMLENDPOINT_response = requests.get(
            'https://portal.sso.' + self.sso_region + '.amazonaws.com/instance/appinstance/' + app_instance_id + '/profiles',
            headers=self.headers,
            cookies=cookies,
        )
        if 'result' not in json.loads(SAMLENDPOINT_response.text).keys():
            raise GetSAMLAssertionError(SAMLENDPOINT_response.text)
        SAMLENDPOINTS = json.loads(SAMLENDPOINT_response.text)['result']
        for endpoint in SAMLENDPOINTS:
            if endpoint['name'] == role_name:
                SAMLENDPOINT = endpoint['url']
        if self.verbose or self.debug:
            print('\n\r   - Getting SAML assertion from portal.sso.' + self.sso_region + '.amazonaws.com using the Access Token...')
            print('\n\rSAMLENDPOINT: ' + SAMLENDPOINT + '\n\r')

        saml_response = requests.get(
            SAMLENDPOINT,
            cookies=cookies,
        )
        encoded_saml = json.loads(saml_response.text)['encodedResponse']
        if self.verbose or self.debug:
            print(encoded_saml)
        return encoded_saml
