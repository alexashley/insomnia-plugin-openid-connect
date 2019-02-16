# insomnia-plugin-openid-connect

## why

Purely for my own interest, and to play around with Insomnia's plugin API. Insomnia already has built-in OAuth 2.0 support, so it can be used with OpenId Connect providers.
That said, this plugin does have a few advantages:

- token & auth endpoint discovery
- backed by an OpenId Connect-certified library ([node-openid-client](https://github.com/panva/node-openid-client))
- one-time configuration from the environment 
- automatically attaches token to resource server requests 

## configuration

The plugin expects the configuration to be passed as an environment setting under an `oidc` key.

| key                  | description                                                                                                                 | default    |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------|------------|
| `additionalScopes`   | Scopes to add to the authentication request                                                                                 | `[]`       |
| `redirectUri`        | Redirect uri for the authorization code flow                                                                                |            |
| `clockTolerance`     | Allowed drift in seconds when making time comparisions                                                                      | `5`        |
| `clientId`           | Client identifier                                                                                                           |            |
| `clientSecret`       | Client secret                                                                                                               |            |
| `grantType`          | OpenId Connect/OAuth 2.0 grant type. Client credentials, authorization code, and resource owner credentials are supported.  | `password` |
| `issuerUri`          | URI of the identity provider. Used for OIDC discovery.                                                                      |            |
| `resourceServerUris` | A list of URIs that require a bearer token to be passed in the authorization header.                                        | `[]`       |
| `username`           | The username of the authenticating user. Only required for the `password` grant.                                            |            |
| `password`           | Only required for the `password` grant.                                                                                     |            |
