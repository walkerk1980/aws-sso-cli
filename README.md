# aws-sso-cli
CLI for logging into AWS SSO Service Directory, retrieving SAML Assertion and setting up .aws/credentials after AssumeRoleWithSAML


usage: ssocli.py [-h] [-i [APPINSTANCEID]] [-r [ROLENAME]] [-v [VERBOSE]]

                 [-u [DIRECTORYURL]] [-d [DIRNAME]] [-n [NETBIOS]]
                 
                 [-l [LOGIN]] [-s [STSREGION]] [-S [SSOREGION]]
                 
                 [-p [PASSWORD]]
                 

optional arguments:

  -h, --help            show this help message and exit
  
  -i [APPINSTANCEID], --appinstanceid [APPINSTANCEID]
  
                        Application instance id. Every AWS account or custom SAML application has a specific id in AWS SSO
                        
  -r [ROLENAME], --rolename [ROLENAME]
  
                        Role name. Actually it is the name of a profile but for practical terms it is the role you will assume
                        
  -v [VERBOSE], --verbose [VERBOSE]
  
                        Verbose mode. For even more information or debugging uncomment the variables' values throughout the script
                        
  -u [DIRECTORYURL], --directoryurl [DIRECTORYURL]
  
                        The URL of your SSO Directory
                        
  -d [DIRNAME], --dirname [DIRNAME]
  
                        The Name of your SSO Directory
                        
  -n [NETBIOS], --netbios [NETBIOS]
  
                        The NETBIOS Name of your SSO Directory
                        
  -l [LOGIN], --login [LOGIN]
  
                        The Active Directory UserName for Login to SSO Directory
                        
  -s [STSREGION], --stsregion [STSREGION]
  
                        The Region to generate AWS STS credentials for and set as config file default
                        
  -S [SSOREGION], --ssoregion [SSOREGION]
  
                        The Region where your SSO Directory resides
                        
  -p [PASSWORD], --password [PASSWORD]
  
                        The Active Directory Password to Login to SSO Directory with User specified by -l
