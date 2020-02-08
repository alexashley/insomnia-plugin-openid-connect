const fetch = require('node-fetch');
const qs = require('querystring');

const realm = 'insomnia';
const keycloakUri = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const username = 'foo';
const password = 'bar';
const clientId = 'insomnia-plugin-openid-connect';
const clientSecret = '256ff4e3-d3b7-4ac7-b67b-5a6336b93fd9';
const redirectUri = 'http://localhost:3030/oidc';

const wait = (seconds) =>
    new Promise((resolve) => setTimeout(resolve, seconds * 1000));

const waitForKeycloakToStart = async () => {
    let attempts = 1;

    while (attempts <= 20) {
        try {
            process.stdout.write(
                `\rwaiting for Keycloak to start (attempt: ${attempts})`
            );

            const response = await fetch(keycloakUri);

            if (response.ok) {
                return;
            }
        } catch (error) {
        }

        attempts++;

        await wait(1);
    }

    throw new Error('Keycloak didn\'t start in the allotted time');
};

const request = async (uri, options) => {
    const {headers = {}, method = 'GET', bodyType = 'json', body} = options;

    const fetchOptions = {
        headers: {
            accept: 'application/json',
            ...headers,
        },
        method,
    };

    if (body && bodyType === 'json') {
        fetchOptions.headers['content-type'] = 'application/json';
        fetchOptions.body = JSON.stringify(body);
    } else if (body && bodyType === 'form') {
        fetchOptions.headers['content-type'] =
            'application/x-www-form-urlencoded';
        fetchOptions.body = qs.stringify(body);
    }

    const response = await fetch(uri, fetchOptions);

    if (!response.ok) {
        throw new Error(
            `${method} ${uri} failed: (${
                response.status
            }): ${await response.text()}`
        );
    }

    if (
        response.headers.has('content-type') &&
        response.headers.get('content-type').includes('application/json')
    ) {
        return response.json();
    }

    return null;
};

const login = async () => {
    const form = {
        client_id: 'admin-cli',
        username: 'keycloak',
        password: 'password',
        grant_type: 'password',
    };

    const response = await request(
        `${keycloakUri}/auth/realms/master/protocol/openid-connect/token`,
        {
            method: 'POST',
            body: form,
            bodyType: 'form',
        }
    );

    return response['access_token'];
};

const createRealm = async (accessToken) =>
    request(`${keycloakUri}/auth/admin/realms`, {
        method: 'POST',
        body: {
            realm,
            enabled: true,
        },
        bodyType: 'json',
        headers: {
            authorization: `bearer ${accessToken}`,
        },
    });

const createUser = async (accessToken) =>
    request(`${keycloakUri}/auth/admin/realms/${realm}/users`, {
        method: 'POST',
        headers: {
            authorization: `bearer ${accessToken}`,
        },
        body: {
            enabled: true,
            username,
            credentials: [
                {
                    temporary: false,
                    type: 'password',
                    value: password,
                },
            ],
        },
    });

const createClient = (accessToken) =>
    request(`${keycloakUri}/auth/admin/realms/${realm}/clients`, {
        method: 'POST',
        headers: {
            authorization: `bearer ${accessToken}`,
        },
        body: {
            clientId,
            enabled: true,
            directAccessGrantsEnabled: true,
            redirectUris: [redirectUri],
            secret: clientSecret,
            serviceAccountsEnabled: true,
        },
    });

(async () => {
    try {
        await waitForKeycloakToStart();

        const accessToken = await login();

        await createRealm(accessToken);
        await Promise.all([createUser(accessToken), createClient(accessToken)]);
    } catch (error) {
        console.error(error);
    }
})();
