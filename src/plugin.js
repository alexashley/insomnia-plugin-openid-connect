const oidc = require('openid-client');
const joi = require('joi');

const TOKEN_CACHE = {};
const CLIENT_CACHE = {};

const DEBUG = false;
const isDebug = () => window.OIDC_DEBUG || DEBUG;

const requireGrantTypePassword = (fieldName) =>
    joi.string().when('grantType', {
        is: 'password',
        then: joi.string().required(),
        otherwise: joi
            .string()
            .valid('', null)
            .default('') // set a valid default here to allow for the key not to be present
            .error(
                new Error(`Grant type must be "password" to set ${fieldName}`)
            ),
    });

const schema = joi.object().keys({
    additionalScopes: joi
        .array()
        .items(joi.string())
        .default([]),
    clockTolerance: joi
        .number()
        .integer()
        .default(5),
    clientId: joi.string().required(),
    // allow the clientSecret to be an empty string for public clients (e.g., mobile apps)
    // that said, it's not recommended for public clients to use direct access grants or the client credentials flow
    clientSecret: joi
        .string()
        .allow('')
        .required(),
    grantType: joi
        .string()
        .valid('password', 'client_credentials', 'authorization_code')
        .default('password'),
    issuerUri: joi
        .string()
        .uri()
        .required(),
    resourceServerUris: joi
        .array()
        .min(1)
        .items(joi.string().uri())
        .required(), // the hostname(s) of the resource server(s) that require the access token
    username: requireGrantTypePassword('username'),
    password: requireGrantTypePassword('password'),
});

const log = (...message) =>
    console.log(
        `[insomnia-plugin-openid-connect] [${new Date().toLocaleTimeString()}]`,
        message.join(' ')
    );
const debug = (...message) => isDebug() && log(...message);

const isAccessTokenValid = (tokens) => {
    if (!(tokens && tokens.access_token)) {
        return false;
    }

    return !tokens.expired();
};

const getOrCreateClient = async (options) => {
    const { clientId, clientSecret, clockTolerance, issuerUri } = options;
    const clientsForIssuer = CLIENT_CACHE[issuerUri] || {};
    let client = clientsForIssuer[clientId];

    if (client) {
        return client;
    }
    const issuer = await oidc.Issuer.discover(issuerUri);

    client = new issuer.Client({
        client_id: clientId,
        client_secret: clientSecret,
    });
    client.CLOCK_TOLERANCE = clockTolerance;

    CLIENT_CACHE[issuerUri] = {
        ...CLIENT_CACHE[issuerUri],
        [clientId]: client,
    };

    return client;
};

const getScope = (additionalScopes) => {
    const scopes = new Set(additionalScopes);

    scopes.add('openid');
    scopes.add('profile');
    scopes.add('email');

    return [...scopes].join(' ');
};

const shouldAuthenticate = (tokens) => {
    return !tokens || tokens.expired();
};

const authenticateOrRefresh = async (config, tokens) => {
    const {
        additionalScopes,
        clientId,
        issuerUri,
        username,
        password,
        grantType,
    } = config;
    const client = await getOrCreateClient(config);

    let newTokens = null;

    if (shouldAuthenticate(tokens)) {
        debug(
            `authenticating to ${issuerUri} with client ${clientId} and grant type: ${grantType}`
        );

        const scope = getScope(additionalScopes);
        const grantOptions = {
            grant_type: grantType,
            scope,
        };

        if (grantType === 'password') {
            grantOptions.username = username;
            grantOptions.password = password;
        }

        newTokens = await client.grant(grantOptions);
    } else {
        debug(
            `refreshing tokens against ${issuerUri} for ${clientId} and grant type: ${grantType}`
        );
        newTokens = await client.refresh(tokens);
    }

    TOKEN_CACHE[createCacheKey(config)] = newTokens;

    return newTokens;
};

const createCacheKey = (config) => {
    const { clientId, issuerUri, grantType, username } = config;

    // combination key to allow for changing username, grant type, or client id without losing track of any tokens
    return [issuerUri, grantType, clientId, username]
        .filter((s) => s)
        .map((s) => encodeURIComponent(s))
        .join(':');
};

const getFromTokenCache = (config) => TOKEN_CACHE[createCacheKey(config)];

module.exports.requestHooks = [
    async (context) => {
        const requestUrl = new URL(context.request.getUrl());
        const env = context.request.getEnvironment();
        const keyName = process.env.OIDC_ENVIRONMENT_NAME || 'oidc';

        if (!(env && env[keyName])) {
            return;
        }

        const config = joi.attempt(
            env[keyName],
            schema,
            'Invalid environment options'
        );
        const resourceServerUri = config.resourceServerUris.find(
            (uri) => new URL(uri).hostname === requestUrl.hostname
        );

        if (!resourceServerUri) {
            return debug(
                `skipping: request host (${
                    requestUrl.hostname
                }) does not match any resource servers: [${config.resourceServerUris.join(
                    ', '
                )}]`
            );
        }

        let tokens = getFromTokenCache(config);

        if (!isAccessTokenValid(tokens)) {
            debug('access token invalid');
            tokens = await authenticateOrRefresh(config, tokens);
        }

        debug('setting authorization header with token', tokens.access_token);
        context.request.setHeader(
            'Authorization',
            `Bearer ${tokens.access_token}`
        );
    },
];
