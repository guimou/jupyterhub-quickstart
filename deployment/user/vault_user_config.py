import hvac

vault_role_id = 'replace with valeria_app approle id' #Obtained when creating approle
vault_secret = 'replace with valeria_app approle secret' #Obtained when creating approle
vault_mount_acc = 'replace with mount accessor' #Obtained with 'vault auth list -detailed'

kc_id = 'user keycloak id'
kc_username = 'user keycloak username'
aws_client = 'user S3 id'
aws_secret = 'user S3 secret'
uid = 'user uid'

vault_client = hvac.Client(url='replace with vault url')
vault_client.auth_approle(vault_role_id,vault_secret)

if vault_client.is_authenticated():
    lookup_response = vault_client.secrets.identity.lookup_entity(
        alias_name=kc_id,
        alias_mount_accessor=vault_mount_acc
    )

    if lookup_response == None:
        entity_create_response = vault_client.secrets.identity.create_or_update_entity(
            name=kc_username
        )

        vault_entity_id = entity_create_response['data']['id']

        alias_create_response = vault_client.secrets.identity.create_or_update_entity_alias(
            name=kc_id,
            canonical_id=vault_entity_id,
            mount_accessor=vault_mount_acc
        )
    else:
        vault_entity_id = lookup_response['data']['id']
                
    print('L''identité Vault est (ID) : ' + vault_entity_id)
    
    vault_client.secrets.kv.v2.create_or_update_secret( 
        path='users/' + vault_entity_id + '/ceph',
        mount_point='valeria',
        secret=dict(AWS_ACCESS_KEY_ID=aws_client,AWS_SECRET_ACCESS_KEY=aws_secret)
    )

    vault_client.secrets.kv.v2.create_or_update_secret( 
        path='users/' + vault_entity_id + '/uid',
        mount_point='valeria',
        secret=dict(uid=uid)
    )

    print('Done')