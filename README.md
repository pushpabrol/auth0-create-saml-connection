# Use this to create a SAML Connection in Auth0 using the provider IDP Metadata

    - inputs folder contains the IDP Metadata file
`.env file contains the settings for this script`


## Environment File Contents
```

DOMAIN=<your auth0 domain>

CLIENT_ID=A client_id with create:connections scope grant on the auth0 management API

CLIENT_SECRET=secret for client above

# Thje IDs of clients in Auth0 that are to be enabled for this connection
ENABLED_CLIENT_IDs=comma separated list of client_ids that are enabled for this connection

```

## Run the script

```
node createoneconnection.js
```
