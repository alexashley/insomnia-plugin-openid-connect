const jwks = require('jwks-rsa');
const jsonwebtoken = require('jsonwebtoken');
const lolex = require('lolex');

const plugin = require('../src/plugin');
const requestHook = plugin.requestHooks[0];

describe('plugin', () => {
    const username = 'foo',
        password = 'bar',
        clientId = 'insomnia-plugin-openid-connect',
        clientSecret = '256ff4e3-d3b7-4ac7-b67b-5a6336b93fd9',
        issuerUri = 'http://localhost:8080/auth/realms/insomnia',
        resourceServerUri = 'http://localhost:3030';

    let validateJwt, options, context;

    beforeAll(async () => {
        const jwksUri = `${issuerUri}/protocol/openid-connect/certs`;
        const client = jwks({ jwksUri });
        const getKey = (header, callback) => {
            client.getSigningKey(header.kid, (err, key) => {
                const signingKey = key.publicKey || key.rsaPublicKey;

                callback(null, signingKey);
            });
        };
        validateJwt = (token) =>
            new Promise((resolve, reject) => {
                jsonwebtoken.verify(
                    token,
                    getKey,
                    {
                        algorithms: ['RS256'],
                        issuer: issuerUri,
                    },
                    (error, decoded) => {
                        if (error) {
                            return reject(error);
                        }

                        resolve(decoded);
                    }
                );
            });
    });

    beforeEach(() => {
        options = {
            clientId,
            clientSecret,
            issuerUri,
            username,
            password,
            grantType: 'password',
            resourceServerUris: [resourceServerUri],
        };

        context = {
            request: {
                getEnvironment: () => ({
                    oidc: options,
                }),
                getUrl: jest.fn().mockReturnValue('http://foobar.org'), // dummy URL so that the plugin ignores the request
                setHeader: jest.fn(),
            },
        };
    });

    afterEach(() => {
        jest.resetAllMocks();
    });

    const getAuthorizationHeaderParts = (callCount = 0) =>
        context.request.setHeader.mock.calls[callCount][1].split(' ');

    describe('options validation', () => {
        it('should require a list of resourceServerUris', async () => {
            delete options.resourceServerUris;

            await expect(requestHook(context)).rejects.toThrow(
                '"resourceServerUris" is required'
            );
        });

        it('should require at least one resource server', async () => {
            options.resourceServerUris = [];

            await expect(requestHook(context)).rejects.toThrow(
                '"resourceServerUris" must contain at least 1 item'
            );
        });

        it('should validate the resource server uri', async () => {
            options.resourceServerUris = ['fake'];

            await expect(requestHook(context)).rejects.toThrow(
                'must be a valid uri'
            );
        });

        ['username', 'password'].forEach((field) => {
            let otherField = field === 'username' ? 'password' : 'username';

            it(`should require ${field} if the grant type is password`, async () => {
                delete options[field];

                await expect(requestHook(context)).rejects.toThrow(
                    `"${field}" is required`
                );
            });

            it(`should not allow ${field} if the grant type is client credentials`, async () => {
                options.grantType = 'client_credentials';
                delete options[otherField];

                await expect(requestHook(context)).rejects.toThrow(
                    `Grant type must be "password" to set ${field}`
                );
            });
        });

        it('should require issuerUri', async () => {
            delete options.issuerUri;

            await expect(requestHook(context)).rejects.toThrow(
                `"issuerUri" is required`
            );
        });

        it('should require issuerUri to be a valid uri', async () => {
            options.issuerUri = 'fake.org';

            await expect(requestHook(context)).rejects.toThrow(
                `"issuerUri" must be a valid uri`
            );
        });
    });

    it('should not set the authorization header if the request uri does not match a resource server', async () => {
        context.request.getUrl.mockReturnValue('http://foobar.org');

        await requestHook(context);

        expect(context.request.setHeader).not.toHaveBeenCalled();
    });

    describe('resource owner credentials flow', () => {
        beforeEach(async () => {
            context.request.getUrl.mockReturnValue(
                `${resourceServerUri}/some/path`
            );

            await requestHook(context);
        });

        it('should set the authorization header', () => {
            expect(context.request.setHeader).toHaveBeenCalledTimes(1);
            expect(context.request.setHeader).toHaveBeenCalledWith(
                'Authorization',
                expect.any(String)
            );
        });

        it('should set bearer as the authentication type', () => {
            const [authType, token] = getAuthorizationHeaderParts();

            expect(authType).toBeTruthy();
            expect(authType.toLowerCase()).toBe('bearer');
            expect(token).toBeTruthy();
        });

        it('should use a JWT signed by the identity provider for the client', async () => {
            const [, token] = getAuthorizationHeaderParts();
            const jwtClaims = await validateJwt(token);

            expect(jwtClaims.azp).toBe(clientId);
        });

        it('should use the resource owner credentials flow', async () => {
            const [, token] = getAuthorizationHeaderParts();
            const jwtClaims = await validateJwt(token);

            expect(jwtClaims.preferred_username).toBe(username);
        });
    });

    describe('client credentials flow', () => {
        beforeEach(async () => {
            context.request.getUrl.mockReturnValue(resourceServerUri);
            options.grantType = 'client_credentials';

            delete options.username;
            delete options.password;

            await requestHook(context);
        });

        it('should set the authorization header', () => {
            expect(context.request.setHeader).toHaveBeenCalledTimes(1);
            expect(context.request.setHeader).toHaveBeenCalledWith(
                'Authorization',
                expect.any(String)
            );
        });

        it('should set bearer as the authentication type', () => {
            const [authType, token] = getAuthorizationHeaderParts();

            expect(authType).toBeTruthy();
            expect(authType.toLowerCase()).toBe('bearer');
            expect(token).toBeTruthy();
        });

        it('should use a JWT signed by the identity provider for the client', async () => {
            const [, token] = getAuthorizationHeaderParts();
            const jwtClaims = await validateJwt(token);

            expect(jwtClaims.azp).toBe(clientId);
        });

        it('should use the client credentials flow', async () => {
            const [, token] = getAuthorizationHeaderParts();
            const jwtClaims = await validateJwt(token);

            expect(jwtClaims.preferred_username).toBe(
                `service-account-${clientId}`
            );
        });
    });

    describe('refresh', () => {
        let clock;

        beforeEach(async () => {
            clock = lolex.install({
                now: new Date(),
                shouldAdvanceTime: true,
            });

            context.request.getUrl.mockReturnValue(resourceServerUri);

            await requestHook(context);
        });

        afterEach(() => {
            clock.uninstall();
        });

        const getNthAccessTokenClaims = (callCount = 0) => {
            const [, token] = getAuthorizationHeaderParts(callCount);

            return validateJwt(token);
        };

        it('should refresh if the access token has expired', async () => {
            const tokenBeforeRefresh = await getNthAccessTokenClaims();
            const time = new Date();
            clock.setSystemTime(tokenBeforeRefresh.exp * 1000);

            await requestHook(context);

            clock.setSystemTime(time.getTime()); // reset the clock so that the token validates
            const tokenAfterRefresh = await getNthAccessTokenClaims(1);

            expect(tokenAfterRefresh.jti).not.toBe(tokenBeforeRefresh.jti);
        });

        it('should re-use non-expired token', async () => {
            const previousToken = await getNthAccessTokenClaims();

            await requestHook(context);

            const tokenAfterRequest = await getNthAccessTokenClaims(1);

            expect(tokenAfterRequest).toEqual(previousToken);
        });
    });
});
