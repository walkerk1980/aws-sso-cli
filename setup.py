#!/usr/bin/env python3

import codecs
from os import path
from platform import system

from setuptools import setup

tests_require = [
    'pytest-runner',
    'pytest',
    'mock',
    'coverage < 4'
]

install_requires = [
    'lxml',
    'click',
    'boto3>=1.9.6',
    'requests[security]',
    'configparser'
]

if system() == 'Windows':
    install_requires.append('requests-negotiate-sspi>=0.3.4')

version = '0.1'

setup(name='aws-sso-cli',
      version='0.1',
      description='CLI for logging into AWS SSO Service Directory, retrieving SAML Assertion and setting up .aws/credentials after AssumeRoleWithSAML',
      url='http://github.com/walkerk1980/aws-sso-cli',
      author='Keith Walker',
      author_email='walkerk1980@gmail.com',
      license='Apache',
      packages=['aws-sso-cli'],
      zip_safe=False)

if __name__ == '__main__':
    setup()