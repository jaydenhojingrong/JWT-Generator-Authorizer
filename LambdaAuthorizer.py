from __future__ import print_function

import re
import logging
import jwt
import time
import boto3
import json

s3_client = boto3.client("s3")

def lambda_handler(event, context):
    
    """Do not print the auth token unless absolutely necessary """
    #print("Client token: " + event['authorizationToken'])
    print("Method ARN: " + event['methodArn'])
    """validate the incoming token"""
    """and produce the principal user identifier associated with the token"""

    """this could be accomplished in a number of ways:"""
    """1. Call out to OAuth provider"""
    """2. Decode a JWT token inline"""
    """3. Lookup in a self-managed DB"""
    principalId = "user|a1b2c3d4"
    tokenVerified = dict()
    scope = str()
    resource_path_verb_list = list()
    isAuthorized = bool()

    """you can send a 401 Unauthorized response to the client by failing like so:"""
    """raise Exception('Unauthorized')"""

    """if the token is valid, a policy must be generated which will allow or deny access to the client"""

    """if access is denied, the client will recieve a 403 Access Denied response"""
    """if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called"""

    """this function must generate a policy that is associated with the recognized principal user identifier."""
    """depending on your use case, you might store policies in a DB, or generate them on the fly"""

    """keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)"""
    """and will apply to subsequent calls to any method/resource in the RestApi"""
    """made with the same token"""

    """the example policy below denies access to all resources in the RestApi"""
    tmp = event['methodArn'].split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    policy = AuthPolicy(principalId, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]

    try:
        tokenVerified = verifyAccessToken(event["authorizationToken"])
        scope = tokenVerified["context"].pop()
        isAuthorized = tokenVerified["isAuthorized"]
        
    except Exception as e:
        policy.denyAllMethods()
        
    if isAuthorized == False:
        policy.denyAllMethods()
    else:
        if "read" in scope:
            resource_path_verb_list.extend(get_resource_path_verb("read"))
            
        if "write" in scope:
            resource_path_verb_list.extend(get_resource_path_verb("write"))
            
        resource_path_verb_list.extend(get_resource_path_verb("default"))
        add_allow_methods_for_role(resource_path_verb_list, policy)
    

    # Finally, build the policy
    authResponse = policy.build()

    return authResponse
    
class HttpVerb:
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    PATCH   = "PATCH"
    HEAD    = "HEAD"
    DELETE  = "DELETE"
    OPTIONS = "OPTIONS"
    ALL     = "*"

class AuthPolicy(object):
    awsAccountId = ""
    """The AWS account id the policy will be generated for. This is used to create the method ARNs."""
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""

    """these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the approriate
    statements for the final policy"""
    allowMethods = []
    denyMethods = []

    
    restApiId = "<<restApiId>>"
    """ Replace the placeholder value with a default API Gateway API id to be used in the policy. 
    Beware of using '*' since it will not simply mean any API Gateway API id, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """    

    region = "<<region>>"
    """ Replace the placeholder value with a default region to be used in the policy. 
    Beware of using '*' since it will not simply mean any region, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """    

    stage = "<<stage>>"
    """ Replace the placeholder value with a default stage to be used in the policy. 
    Beware of using '*' since it will not simply mean any stage, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = ("arn:aws:execute-api:" +
            self.region + ":" +
            self.awsAccountId + ":" +
            self.restApiId + "/" +
            self.stage + "/" +
            verb + "/" +
            resource)


        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            statements.append(statement)

        return statements

    def allowAllMethods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId' : self.principalId,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Deny", self.denyMethods))

        return policy

def returnJWTCheckerResponse(isAuthorized, other_params={}):
    return {"isAuthorized": isAuthorized, "context": other_params}

def verifyAccessToken(token):

    current_time = int(time.time())

    try:
        # check token structure
        if len(token.split(".")) != 3:
            print (0)
            return returnJWTCheckerResponse(isAuthorized=False, other_params={})
            
    except Exception as e:
        print (1)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})
        
    try:
        # get unverified headers
        headers = jwt.get_unverified_header(token)
        # validating exp, iat, signature, iss
        
        # get content from s3 openid-configuration.json
        # extract jwks_uri from matching issuer 
        # get content from s3 jwks_uri
        # loop to find matching kid and get its public key
        print(headers)
        public = get_public_key(headers["iss"], headers["kid"])
        print (public)
        print("xxxxxx")
        data = jwt.decode(
            token,
            key="-----BEGIN PUBLIC KEY-----\n"+ public +"\n-----END PUBLIC KEY-----",
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
                "require": ["exp", "iat", "scope"]
            },
            audience= "https://g2t5.com"
        )
        # check if iat is before the current time in UTC? return true! cannot be issued in the "future"
        if data["iat"] > current_time:
            print (2)
            return returnJWTCheckerResponse(isAuthorized=False, other_params={"iat is after the current UTC time"})
    
    except jwt.InvalidSignatureError as e:
        print (3)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})

    except jwt.DecodeError as e:
        print (4)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})

    except jwt.ExpiredSignatureError as e:
        print (5)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})

    except jwt.InvalidIssuerError as e:
        print (6)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})
        
    except jwt.InvalidIssuedAtError as e:
        print (7)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})

    except jwt.InvalidTokenError as e:
        print (8)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})

    except Exception as e:
        print (9)    
        print (e)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})
    
    try:
        # scope check
        if "openid" not in data.get("scope").split(" "):
            print (10)
            return returnJWTCheckerResponse(isAuthorized=False, other_params={"scope not OIDC"})

    except Exception as e:
        print (11)
        return returnJWTCheckerResponse(isAuthorized=False, other_params={e})


    return returnJWTCheckerResponse(isAuthorized=True, other_params={data["scope"]})

def add_allow_methods_for_role(resource_path_verb_list, policy):
    for item in resource_path_verb_list:
        verb, resource_path = item.split(":")
        policy.allowMethod(verb, resource_path)
        
    
def get_public_key(issuer_input, kid_input):
   S3_BUCKET_NAME = 'g2t5-openid-configuration'
   object_key = get_jwks_uri_object_key(issuer_input)
   file_content = get_S3_file_content(object_key, S3_BUCKET_NAME)
   for key in file_content["keys"]:
       if key["kid"] == kid_input:
           return key["x5c"][0]
   return None

def get_jwks_uri_object_key(issuer_input):
    S3_BUCKET_NAME = 'g2t5-openid-configuration'
    file_content = get_S3_file_content(".well-known/openid-configuration.json", S3_BUCKET_NAME)
    for issuer in file_content:
        if issuer["issuer"] == issuer_input:
            jwks_uri = issuer["jwks_uri"]
            return jwks_uri[jwks_uri.find(".com")+5:]

def get_resource_path_verb(scope):
    S3_BUCKET_NAME = "g2t5-roles-definition"
    file_content = get_S3_file_content("roles.json", S3_BUCKET_NAME)
    resource_path_verb_list = file_content[scope]
    return resource_path_verb_list

def get_S3_file_content(name, S3_BUCKET_NAME):
    object_key = name
    file_content = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=object_key)["Body"].read()
    file_content = file_content.decode('utf-8')
    return json.loads(file_content)