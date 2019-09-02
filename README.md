Valeria - Jupyterhub
====================

This repository contains the JupyterHub version used in the Valeria project, created at [Université Laval](https://www.ulaval.ca).

Valeria is a datascience platform providing researchers and students at ULaval with a shared datalake based on Ceph, on-demand Jupyter Notebooks running on OpenShift, and other various tools to collect, clean, store and analyze their data.

Based on Jupyter-on-OpenShift (see Credits), it is tailored to fit in ULaval environment, with some specific changes required for the Valeria Platform. Basically those changes are:
* Upgrade of JupyterHub to 1.0.0, along with other libraries.
* Use of an external PostgreSQL database for JupyterHub (as we already have a PgSQL cluster).
* Use of an external RedHat SSO (Keycloak) for OAuth authentication (as we already have this environment for Valeria).
* Connection to an Hashicorp Vault instance at notebook spawn time to retrieve user's S3 secrets and uid, launching the NB with this uid and injecting S3 secrets as environment variables. uid is for connection to an NFS storage with correct permissions. S3 secrets are for direct connection to buckets (ability to browse from the notebook), and of course usage in scripts without saving those secrets in the code.
* Custom OAuthenticator classes to refresh tokens and retrieve secrets from Vault at spawn time.
* Custom [notebooks](https://github.com/ulaval/valeria-jupyter-notebooks-s3) with different flavors (SciPy, R...) which:
  * Connect a /home and a /scratch dir through an NFS volume to an existing Lustre cluster.
  * Connect all available buckets in the datalake to /datalake_bucket[A,B,...] folders.

Again this JupyterHub version was desgined for Valeria, but several concepts can be reused, and it can totally be replicated elsewhere.

Acknowledgements
----------------
Designed to to run on OpenShift, this JupyterHub version is heavily based on the fantastic work done by Graham Dumpleton (@GrahamDumpleton) with Jupyter-on-OpenShift, especially [JupyterHub-Quickstart](https://github.com/jupyter-on-openshift/jupyterhub-quickstart). Please read what's on this project for more details on certain aspects.
We want to also acknowledge the work from [PGContents](https://github.com/quantopian/pgcontents) for the HybridContentsManager and [S3Contents](https://github.com/danielfrg/s3contents) for the S3ContentsManager.


Installation
============
Requirements
------------
To replicate the same environment several things are needed:
* A [PostgreSQL](https://www.postgresql.org/) database. The deployment template will need:
  * DB host
  * DB name
  * DB username (stored in a secret)
  * DB password (stored in a secret)
* A [Keycloak](https://www.keycloak.org/) or Red Hat SSO instance. The deployment template will need:
  * Keycloak (KC) hostname
  * KC realm
  * KC token URL
  * KC authorize URL
  * KC userdata URL
  * KC username Key
  * KC OAuth client id (stored in a secret)
  * KC OAuth client secret (stored in a secret)
* A [Hashicorp Vault](https://www.vaultproject.io/) instance. The deployment template will need:
  * Vault URL
* A S3 Compatible storage (this project runs with [Ceph](https://ceph.io/)). The deployment template will need:
  * The S3 endpoint URL
* A NFS storage. The deployment template will need:
  * The NFS server address
  * The NFS path of the export

Preparation
-----------
### PostgreSQL Database
* Create the database and a user with CRUD rights

### Keycloak
* Create a proper realm (valeria in this walkthrough).
* Create a client with the following configuration : 
  * Client ID : your_client_id
  * Client protocol : openid-connect
  * Acces type : public (since we want everything to be client side)
  * Standard flow enabled : On
  * Implicit flow : Off
  * Direct access grants enabled : Off
  * Valid redirect URIs : JupyterHub URL, eventually a web portal,...

### Vault
* In the following configurations VAULT_ADDR and VAULT_TOKEN have been set as environments variables for the vault commands.
* Create a secret engine using [KV secrets engine v2](https://www.vaultproject.io/docs/secrets/kv/kv-v2.html) (named 'valeria' in this walkthrough)
``` bash
vault secrets enable -path=valeria -version=2 kv
```
* Define a policy that will allow authenticated users to manage their secrets, and only theirs. This is a dynamic policy bound the corresponding authenticated user.
```
valeria.hcl:
------------
path "valeria/data/users/{{identity.entity.id}}/*" {
  capabilities = ["create", "update", "read", "delete"]
}

path "valeria/metadata/{{identity.entity.id}}/*" {
  capabilities = ["list"]
}
```
* Create and bind an approle to this policy.
```
vault policy write valeria valeria.hcl
```
* Enable JWT authentication and bind the valeria policy.
```
vault auth enable jwt

vault write auth/jwt/role/valeria \
    bound_audiences="vault-valeria" \
    allowed_redirect_uris="https://your_vault_server/ui/vault/auth/oidc/oidc/callback" \
    user_claim="sub" \
    policies="valeria"

vault write /auth/jwt/config \  
    oidc_discovery_url="https://your_keycloak_server/auth/realms/valeria" \
    oidc_client_id="your_client_id" \
    oidc_client_secret="your_client_secret" \
    default_role="valeria"
```
* Define a policy that will allow a script or an application to create a update a user's secret (but not read it!).
```
valeria_app.hcl:
----------------
path "identity/lookup/entity" {
  capabilities = ["create", "update"]
}

path "identity/*" {
  capabilities = ["create", "update"]
}

path "valeria/data/users/*" {
  capabilities = ["create", "update"]
}
```
* Create and bind an approle to this policy. In this example the policy we just created is called valeria_app.hcl. Replace IPs by the ip or ranges that will access Vault with this approle to further secure it.
```
vault policy write valeria_app valeria_app.hcl

vault write /auth/approle/role/valeria bind_secret_id=true bound_cidr_list=IP1,Range1,Range2 local_secret_ids=false policies=valeria_app secret_id_bound_cidrs=IP1,Range1,Range2 token_bound_cidrs=IP1,Range1,Range2 token_ttl=1m token_type=default
```

### Prepare the JupyterHub image
* Create a project in OpenShift, and make sure to work in it for the following commands.
* Note: JupyterHub images are built locally with the s2i tool as we found this to be faster than building in our OpenShift test environments. Buildconfg files can be found on the [JupyterHub-Quickstart](https://github.com/jupyter-on-openshift/jupyterhub-quickstart) repo if you want to keep the original method (which has a lot of advantages).
* Build the base JupyterHub image:
```
s2i --ref=prod --context-dir=jupyterhub build https://github.com/ulaval/valeria-jupyterhub.git centos/python-36-centos7 jupyterhub
```
* Build the Valeria custom JupyterHub image:
```
s2i --ref=prod --context-dir=jupyterhub-valeria build https://github.com/ulaval/valeria-jupyterhub.git jupyterhub jupyterhub-ul-test
```
* Push the JupyterHub and Notebooks images to your project.


### Prepare the notebooks image and service account
* Build the notebooks with the S3 features by importing the build configs (proceed in the same way for the other required notebooks)
```
oc create -f https://raw.githubusercontent.com/ulaval/valeria-jupyter-notebooks-s3/master/build-configs/s2i-minimal-notebook-s3.json
```
* To be able to mount NFS and get the right uid, the notebooks must run under a specific service account with a custom scc (restricted+nfs mount rights). Customize the scc in deployment/scc along your needs (uid range). Note that you must be cluster admin for this operation.
```
oc create -f scc-notebook.yaml
oc create serviceaccount notebook -n jupyterhub
oc adm policy add-scc-to-user notebook -z notebook
```

Deployment of JupyterHub
------------------------
* Edit the templates/secrets.yaml file and fill in the required fields:
  * OAuth and BD information are self-explanatory
  * cookie_secret should be 32 random bytes, encoded as hex, used to encrypt the browser cookies which are used for authentication (https://jupyterhub.readthedocs.io/en/stable/getting-started/security-basics.html#cookie-secret)
  * crypt_key sould be a hex-encoded 32-byte key, used to encrypt persisted authentication data (ref. https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#authentication-state)
* Create the secrets:
```
oc create -f secrets.yaml
```
* From templates/jupyterhub-ul.json, create the deployment template:
```
oc create -f jupyterhub-ul.json
```
* Use the template to deploy the project, with all the required values.

Account creation workflow
-------------------------
There are multiple operations to execute for a user onboarding. In a prodcution environment everything should be of course automated.
* Create the user in Keycloak (we will need its keycloak id and username).
* Create the user in the system from which you will export the NFS (we will need it uid).
* Create an account for this user in your S3 provider (we will need its key and secret).
* Using the example script in deployment/user, populate Vault with the user information.
* When aythenticated against Keycloak, the user will now fetch its information automatically from Vault at Notebook spawn time, and this one will make the connections automatically to NFS and S3.









