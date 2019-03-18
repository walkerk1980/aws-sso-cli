from setuptools import setup

setup(name='aws-sso-cli',
      version='0.1',
      description='CLI for logging into AWS SSO Service Directory, retrieving SAML Assertion and setting up .aws/credentials after AssumeRoleWithSAML',
      url='http://github.com/walkerk1980/aws-sso-cli',
      author='Keith Walker',
      author_email='walkerk1980@gmail.com',
      license='Apache',
      packages=['aws-sso-cli'],
      zip_safe=False)

