# insomnia-plugin-openid-connect

## why

Insomnia already has built-in OAuth 2.0 support, so it should be compatible with OIDC identity providers.
I mostly made this plugin for fun, but it does have a few advantages:

- uses an OpenId Connect-certified library ([node-openid-client](https://github.com/panva/node-openid-client))
- one-time configuration from the environment 
- automatically attaches tokens to resource server requests 
