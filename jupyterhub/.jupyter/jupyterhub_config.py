import os
import warnings
from ulkubespawner import ULKubeSpawner

# Load custom spawner class to integrate images list and container specs
c.JupyterHub.spawner_class = ULKubeSpawner

# Initialize environment
c.Spawner.environment = {}

# Keep Spark vars in notebooks
c.Spawner.env_keep = ['PYSPARK_SUBMIT_ARGS', 'PYSPARK_DRIVER_PYTHON', 'PYSPARK_DRIVER_PYTHON_OPTS', 'SPARK_HOME', 'SPARK_CLUSTER', 'PYTHONPATH']


# Enable JupyterLab interface if enabled.  TODO: Replace by result from form
if os.environ.get('JUPYTERHUB_ENABLE_LAB', 'false').lower() in ['true', 'yes', 'y', '1']:
    c.Spawner.environment.update(dict(JUPYTER_ENABLE_LAB='true'))

# Setup location for customised template files.
c.JupyterHub.template_paths = ['/opt/app-root/src/templates']

# Configure KeyCloak as authentication provider.
from openshift import client, config

with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace') as fp:
    namespace = fp.read().strip()

config.load_incluster_config()
oapi = client.OapiApi()

routes = oapi.list_namespaced_route(namespace)

def extract_hostname(routes, name):
    for route in routes.items:
        if route.metadata.name == name:
            return route.spec.host

jupyterhub_name = os.environ.get('JUPYTERHUB_SERVICE_NAME')
jupyterhub_hostname = extract_hostname(routes, jupyterhub_name)

keycloak_hostname = 'keycloak-valeriademo.svd-pca.svc.ulaval.ca'

keycloak_realm = os.environ.get('KEYCLOAK_REALM')

keycloak_account_url = 'https://%s/auth/realms/%s/account' % (keycloak_hostname, keycloak_realm)

with open('templates/vars.html', 'w') as fp:
    fp.write('{%% set keycloak_account_url = "%s" %%}' % keycloak_account_url)

# Get OAuth2 configuration
os.environ['OAUTH2_TOKEN_URL'] = 'https://%s/auth/realms/%s/protocol/openid-connect/token' % (keycloak_hostname, keycloak_realm)
os.environ['OAUTH2_AUTHORIZE_URL'] = 'https://%s/auth/realms/%s/protocol/openid-connect/auth' % (keycloak_hostname, keycloak_realm)
os.environ['OAUTH2_USERDATA_URL'] = 'https://%s/auth/realms/%s/protocol/openid-connect/userinfo' % (keycloak_hostname, keycloak_realm)
os.environ['OAUTH2_TLS_VERIFY'] = '0'
os.environ['OAUTH_TLS_VERIFY'] = '0'
os.environ['OAUTH2_USERNAME_KEY'] = 'preferred_username'

from oauthenticator.generic import GenericOAuthenticator
from tornado import gen

# Pre-Spawn custom class to retrieve secrets from Vault using user access token
class EnvGenericOAuthenticator(GenericOAuthenticator):

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        import hvac
        import pprint
        auth_state = yield user.get_auth_state()
        print(auth_state)
        if not auth_state:
            # user has no auth state
            return
        username=spawner.user.name
        vault_url = os.environ['VAULT_URL']
        client = hvac.Client(url=vault_url)
        client.token = auth_state['access_token']
        if client.is_authenticated():
            secret_version_response = client.secrets.kv.v2.read_secret_version(
                mount_point='valeria',
                path='users/' + username + '/ceph',
            )   
            AWS_ACCESS_KEY_ID = secret_version_response['data']['data']['AWS_ACCESS_KEY_ID']
            AWS_SECRET_ACCESS_KEY = secret_version_response['data']['data']['AWS_SECRET_ACCESS_KEY']
        else:
            AWS_ACCESS_KEY_ID = 'none'
            AWS_SECRET_ACCESS_KEY = 'none'
        # Retrieve S3ContentManager infomation and update env var to pass to notebooks
        s3_endpoint_url = os.environ.get('S3_ENPOINT_URL')
        spawner.environment.update(dict(S3_ENPOINT_URL=s3_endpoint_url,AWS_ACCESS_KEY_ID=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY=AWS_SECRET_ACCESS_KEY))

if 'JUPYTERHUB_CRYPT_KEY' not in os.environ:
    warnings.warn(
        "Need JUPYTERHUB_CRYPT_KEY env for persistent auth_state.\n"
        "    export JUPYTERHUB_CRYPT_KEY=$(openssl rand -hex 32)"
    )
    c.CryptKeeper.keys = [ os.urandom(32) ]


# Configure authenticator
c.JupyterHub.authenticator_class = EnvGenericOAuthenticator
c.GenericOAuthenticator.login_service = "KeyCloak"
c.GenericOAuthenticator.oauth_callback_url = 'https://%s/hub/oauth_callback' % jupyterhub_hostname
c.GenericOAuthenticator.client_id = os.environ.get('OAUTH_CLIENT_ID')
c.GenericOAuthenticator.client_secret = os.environ.get('OAUTH_CLIENT_SECRET')
c.GenericOAuthenticator.tls_verify = False
# enable authentication state
c.GenericOAuthenticator.enable_auth_state = True


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
