Valeria - Jupyterhub
====================

This repository contains the JupyterHub version used in the project Valeria, created at [Université Laval](https://www.ulaval.ca).

Valeria is a datascience platform providing researchers and students with a shared datalake based on Ceph, on-demand Jupyter Notebooks running on OpenShift, and other various tools to collect, clean, store and analyze their data.

It is tailored to fit in Université Laval's environment, with some specific add-ons required for the Valeria Platform. Basically those modifications are:
* Upgrade of JupyterHub to 1.0.0, along with other libraries,
* Use of an external PostgreSQL database for JupyterHub as we already have a PgSQL cluster,
* Use of an external RedHat SSO (Keycloak) for OAuth authentication as we already have the environment for Valeria,
* Connection to an Hashicorp Vault instance at notebook spawn time to retrieve user's S3 secrets and uid, launching the NB with the right uid and injecting S3 secrets as environment variables, 
* Custom OAuthenticator classes to refresh tokens and retrieve secrets from Vault at spawn time,
* Custom [notebooks](https://github.com/ulaval/valeria-jupyter-notebooks-s3) with different flavors (SciPy, R...) which:
  * Connect a /home and a /scratch dir through an NFS volume to an existing Lustre cluster (notebook uid controls acces to filesystem)
  * Connect all available buckets in the datalake to /datalake_bucket[A,B,...] folders

Again this JupyterHub version was tailored for Valeria, but several concepts can be reused, and it can totally be replicated elsewhere.

Credits
-------
Designed to to run on OpenShift, this JupyterHub version is heavily based on the fantastic work done by Graham Dumpleton (@GrahamDumpleton) with the Jupyter-on-OpenShift, especially [JupyterHub-Quickstart](https://github.com/jupyter-on-openshift/jupyterhub-quickstart). Please read what's on this project for more details on certain aspects.
We want to also acknowledge the work from [PGContents](https://github.com/quantopian/pgcontents) for the HybridContentsManager and [S3Contents](https://github.com/danielfrg/s3contents) for the S3ContentsManager.



