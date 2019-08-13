import os
import warnings
from jinja2 import Template
from kubespawner import KubeSpawner


# Custom class to personalize templates
class ULKubeSpawner(KubeSpawner):
    def _options_form_default(self):
        with open('/opt/app-root/src/templates/select.html') as file_:
            template = Template(file_.read())
        with open('/opt/app-root/configs/image_list.txt') as fp:
            content = fp.read().strip()
            if content:
                image_list = content
        return template.render(image_list=image_list)

    def options_from_form(self, formdata):
        try:
            self.cpu_limit = float(formdata.get('cpu_limit')[0])
            self.mem_limit = formdata.get('mem_limit')[0] + 'M'
            self.image_spec = formdata.get('image_spec')[0]
        except:
            raise Exception(str(formdata))

        if 'jupyterlab' in formdata.get('options', []):
            self.cmd = ['jupyter-labhub']
            self.default_url = '/lab'
        
        return formdata

# Load custom spawner class to integrate images list and container specs
c.JupyterHub.spawner_class = ULKubeSpawner

# Initialize environment
c.Spawner.environment = {}

# Keep Spark vars in notebooks
c.Spawner.env_keep = ['PYSPARK_PYTHON','PYSPARK_SUBMIT_ARGS', 'PYSPARK_DRIVER_PYTHON', 'PYSPARK_DRIVER_PYTHON_OPTS', 'SPARK_HOME', 'SPARK_CLUSTER', 'PYTHONPATH']


# Enable JupyterLab interface if enabled.  TODO: Replace by result from form
if os.environ.get('JUPYTERHUB_ENABLE_LAB', 'false').lower() in ['true', 'yes', 'y', '1']:
    c.Spawner.environment.update(dict(JUPYTER_ENABLE_LAB='true'))

# Setup location for customised template files.
c.JupyterHub.template_paths = ['/opt/app-root/src/templates']

# Configure Jupyterhub hostname
from kubernetes import client, config
from openshift.dynamic import DynamicClient

with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace') as fp:
    namespace = fp.read().strip()

config.load_incluster_config()
dyn_client = DynamicClient(ApiClient())

v1_routes = dyn_client.resources.get(api_version='route.openshift.io/v1', kind='Route')
routes = v1_routes.get(namespace=namespace)

def extract_hostname(routes, name):
    for route in routes.items:
        if route.metadata.name == name:
            return route.spec.host

jupyterhub_name = os.environ.get('JUPYTERHUB_SERVICE_NAME')
jupyterhub_hostname = extract_hostname(routes, jupyterhub_name)


# Pre-Spawn custom class to retrieve secrets from Vault using user access token
from oauthenticator.generic import GenericOAuthenticator
from tornado import gen

class EnvGenericOAuthenticator(GenericOAuthenticator):
    # Before spawning the notebook, we retrieve some information from Vault
    async def pre_spawn_start(self, user, spawner):
        print('Entering pre_spawn') #TODO remove
        import hvac
        import json
        import requests

        # Retrieve user authentication info from JH
        auth_state = await user.get_auth_state()
        if not auth_state:
            # user has no auth state
            return
        
        # Retrieve information from Vault                
        try:
            # Login to Vault with JWT 
            vault_url = os.environ['VAULT_URL']
            vault_login_url = vault_url + '/v1/auth/jwt/login'
            vault_login_json = {"role":None, "jwt": auth_state['access_token']}
            vault_response_login = requests.post(url = vault_login_url, json = vault_login_json).json()

            # Retrieve user entity id and Vault access token
            vault_token = vault_response_login['auth']['client_token']
            vault_entity_id = vault_response_login['auth']['entity_id']
        
            # Retrieve S3 credentials and user uid
            vault_client = hvac.Client(url=vault_url, token=vault_token)
            if vault_client.is_authenticated():
                secret_version_response = vault_client.secrets.kv.v2.read_secret_version(
                    mount_point='valeria',
                    path='users/' + vault_entity_id + '/ceph',
                )   
                AWS_ACCESS_KEY_ID = secret_version_response['data']['data']['AWS_ACCESS_KEY_ID']
                AWS_SECRET_ACCESS_KEY = secret_version_response['data']['data']['AWS_SECRET_ACCESS_KEY']
                secret_version_response = vault_client.secrets.kv.v2.read_secret_version(
                    mount_point='valeria',
                    path='users/' + vault_entity_id + '/uid',
                )
                spawner.uid = secret_version_response['data']['data']['uid']
            else:
                AWS_ACCESS_KEY_ID = None
                AWS_SECRET_ACCESS_KEY = None
                uid = None

        except:
            print('No Vault connection')
            AWS_ACCESS_KEY_ID = None
            AWS_SECRET_ACCESS_KEY = None
            uid = None

        # Retrieve S3ContentManager infomation and update env var to pass to notebooks
        s3_endpoint_url = os.environ.get('S3_ENDPOINT_URL')
        spawner.environment.update(dict(S3_ENDPOINT_URL=s3_endpoint_url,AWS_ACCESS_KEY_ID=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY=AWS_SECRET_ACCESS_KEY))
    
    # Refresh user access and refresh tokens (called periodically)
    async def refresh_user(self, user, handler=None):
        import jwt
        import time
        import urllib
        import json
        from tornado.httpclient import HTTPRequest, AsyncHTTPClient
        from tornado.httputil import url_concat
        print('Entering refresh') #TODO remove
        # Retrieve user authentication info, decode, and check if refresh is needed
        auth_state = await user.get_auth_state()
        print(auth_state['access_token']) #TODO remove
        decoded = jwt.decode(auth_state['access_token'], verify=False)
        diff=decoded['exp']-time.time()
        print(diff) #TODO remove
        if diff>0:
            # Access token still valid, function returs True
            refresh_user_return = True
        else:
            # We need to refresh access token (which will also refresh the refresh token)
            refresh_token = auth_state['refresh_token']
            http_client = AsyncHTTPClient()
            url = os.environ.get('OAUTH2_TOKEN_URL')
            params = dict(
                grant_type = 'refresh_token',
                client_id = os.environ.get('OAUTH_CLIENT_ID'),
                client_secret = os.environ.get('OAUTH_CLIENT_SECRET'),
                refresh_token = refresh_token
            )
            
            headers = {
            "Content-Type": "application/x-www-form-urlencoded"
            }
            
            req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )

            resp = await http_client.fetch(req)

            resp_json = json.loads(resp.body.decode('utf8', 'replace'))

            access_token = resp_json['access_token']
            refresh_token = resp_json.get('refresh_token', None)
            token_type = resp_json['token_type']
            scope = resp_json.get('scope', '')
            if (isinstance(scope, str)):
                scope = scope.split(' ')

            # Determine who the logged in user is
            headers = {
                "Accept": "application/json",
                "User-Agent": "JupyterHub",
                "Authorization": "{} {}".format(token_type, access_token)
            }
            if self.userdata_url:
                url = url_concat(self.userdata_url, self.userdata_params)
            else:
                raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

            if self.userdata_token_method == "url":
                url = url_concat(self.userdata_url, dict(access_token=access_token))

            req = HTTPRequest(url,
                            method=self.userdata_method,
                            headers=headers,
                            validate_cert=self.tls_verify,
                            )
            resp = await http_client.fetch(req)
            resp_json = json.loads(resp.body.decode('utf8', 'replace'))

            if not resp_json.get(self.username_key):
                self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
                return
            
            refresh_user_return = {
                'name': resp_json.get(self.username_key),
                'auth_state': {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'oauth_user': resp_json,
                    'scope': scope,
                }
            }
        print(str(refresh_user_return))
        return refresh_user_return
        

if 'JUPYTERHUB_CRYPT_KEY' not in os.environ:
    warnings.warn(
        "Need JUPYTERHUB_CRYPT_KEY env for persistent auth_state.\n"
        "    export JUPYTERHUB_CRYPT_KEY=$(openssl rand -hex 32)"
    )
    c.CryptKeeper.keys = [ os.urandom(32) ]

# Configure KeyCloak as authentication provider.
keycloak_hostname = os.environ.get('KEYCLOAK_HOSTNAME')
keycloak_realm = os.environ.get('KEYCLOAK_REALM')
keycloak_account_url = 'https://%s/auth/realms/%s/account' % (keycloak_hostname, keycloak_realm)

c.JupyterHub.authenticator_class = EnvGenericOAuthenticator
# Following line: workaround to make OAuth work, reference: https://github.com/jupyterhub/oauthenticator/issues/271
c.JupyterHub.authenticator_class.login_handler._OAUTH_AUTHORIZE_URL = 'https://%s/auth/realms/%s/protocol/openid-connect/auth' % (keycloak_hostname, keycloak_realm)
c.GenericOAuthenticator.login_service = "Valeria"
c.GenericOAuthenticator.oauth_callback_url = 'https://%s/hub/oauth_callback' % jupyterhub_hostname
c.GenericOAuthenticator.client_id = os.environ.get('OAUTH_CLIENT_ID')
c.GenericOAuthenticator.client_secret = os.environ.get('OAUTH_CLIENT_SECRET')
c.GenericOAuthenticator.tls_verify = False
# Enable authentication state
c.GenericOAuthenticator.enable_auth_state = True
# Force refresh of tokens before spawning
c.GenericOAuthenticator.refresh_pre_spawn = True

# Setup persistent storage on NFS
c.KubeSpawner.service_account = 'notebook'
# c.KubeSpawner.uid=uid # TODO Remove
c.KubeSpawner.volumes = [
    {
        'name': 'home',
        'nfs': {
            'server': '10.250.111.190',
            'path': '/mnt/nfsexport'
        }
    }
]
c.KubeSpawner.volume_mounts = [
    {
        'name': 'home',
        'mountPath': '/users'
    }
]

# Start Notebook in user directory
c.KubeSpawner.notebook_dir = '/users'
c.KubeSpawner.default_url = '/tree/home/' + {username}


# Populate admin users and use white list from config maps.
if os.path.exists('/opt/app-root/configs/admin_users.txt'):
    with open('/opt/app-root/configs/admin_users.txt') as fp:
        content = fp.read().strip()
        if content:
            c.Authenticator.admin_users = set(content.split())

if os.path.exists('/opt/app-root/configs/user_whitelist.txt'):
    with open('/opt/app-root/configs/user_whitelist.txt') as fp:
        content = fp.read().strip()
        if content:
            c.Authenticator.whitelist = set(content.split())


# Setup culling of idle notebooks if timeout parameter is supplied.
idle_timeout = os.environ.get('JUPYTERHUB_IDLE_TIMEOUT')
if idle_timeout and int(idle_timeout):
    c.JupyterHub.services = [
        {
            'name': 'cull-idle',
            'admin': True,
            'command': ['cull-idle-servers', '--timeout=%s' % idle_timeout],
        }
    ]

# Allow shutdown of Hub while leaving Notebooks running, allowing for non-disruptive updates. The Hub should be able to resume from database state.
c.JupyterHub.cleanup_servers = False


