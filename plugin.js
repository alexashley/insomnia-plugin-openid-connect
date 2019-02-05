const oidc = require('openid-client');
const joi = require('joi');

const requireGrantTypePassword = (fieldName) => joi.string().when('grantType', {
    is: 'password',
    then: joi.string().required(),
    otherwise: joi.string()
        .valid('', null)
        .default('') // set a valid default here to allow for un-setting the key
        .error(new Error(`Grant type must be 'password' to set ${fieldName}`)),
});

const schema = joi.object().keys({
    additionalScopes: joi.array().items(joi.string()).default([]),
    clientId: joi.string().required(),
    // allow the clientSecret to be an empty string for public clients (e.g., mobile apps)
    // that said, it's not recommended for public clients to use direct access grants or the client credentials flow
    clientSecret: joi.string().allow('').required(),
    grantType: joi.string().valid('password', 'client_credentials').default('password'),
    issuerUri: joi.string().uri().required(),
    username: requireGrantTypePassword('username'),
    password: requireGrantTypePassword('password'),
});
