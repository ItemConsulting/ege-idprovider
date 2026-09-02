const test = require('/lib/xp/testing');

function mockWellKnownService() {
    test.mock('/lib/configFile/wellKnownService', {
        cacheIdProviderConfig: function (idProviderName, configAsString) {
            // to do nothing
        },
        getIdProviderConfig: function (idProviderName) {
            return null;
        },
        getWellKnownConfiguration: function (endpoint) {
            return {
                'issuer': 'issuer',
                'authorization_endpoint': 'authorizationUrl',
                'token_endpoint': 'tokenUrl',
                'userinfo_endpoint': 'userinfoUrl',
                'jwks_uri': 'jwksUri',
            }
        }
    });
}

exports.testValidConfig = () => {
    mockWellKnownService();

    test.mock('/lib/configFile/services/getConfig', {
        getConfigOrEmpty: function () {
            return {
                'idprovider.myidp.displayName': 'displayName',
                'idprovider.myidp.description': 'description',

                'idprovider.myidp.usePkce': 'false',
                'idprovider.myidp.issuer': 'custom_issuer',
                'idprovider.myidp.authorizationUrl': 'custom_authorizationUrl',
                'idprovider.myidp.tokenUrl': 'custom_tokenUrl',
                'idprovider.myidp.userinfoUrl': 'custom_userinfoUrl',
                'idprovider.myidp.jwksUri': 'custom_jwksUri',
                'idprovider.myidp.useUserinfo': 'false',
                'idprovider.myidp.method': 'post',
                'idprovider.myidp.scopes': 'name  profile email     nikname',
                'idprovider.myidp.clientId': 'clientId',
                'idprovider.myidp.clientSecret': 'clientSecret',
                'idprovider.myidp.defaultGroups': 'group:myidp:default group:myidp:dev',
                'idprovider.myidp.claimUsername': 'username',

                'idprovider.myidp.additionalEndpoints.0.name': 'name0',
                'idprovider.myidp.additionalEndpoints.0.url': 'url0',
                'idprovider.myidp.additionalEndpoints.1.name': 'name1',
                'idprovider.myidp.additionalEndpoints.1.url': 'url1',

                'idprovider.myidp.mappings.displayName': '@@{nikname} - @@{userinfo.name}',
                'idprovider.myidp.mappings.email': '@@{email}',
                'idprovider.myidp.mappings.emailFallback': '@@{userinfo.upn}',

                'idprovider.myidp.endSession.url': 'endSessionUrl',
                'idprovider.myidp.endSession.idTokenHintKey': 'idTokenHintKey',
                'idprovider.myidp.endSession.postLogoutRedirectUriKey': 'postLogoutRedirectUriKey',
                'idprovider.myidp.endSession.additionalParameters.0.key': 'k0',
                'idprovider.myidp.endSession.additionalParameters.0.value': 'v0',
                'idprovider.myidp.endSession.additionalParameters.1.key': 'k1',
                'idprovider.myidp.endSession.additionalParameters.1.value': 'v1',

                'idprovider.myidp.rules.forceEmailVerification': 'true',

                'idprovider.myidp.autoLogin.createUser': 'true',
                'idprovider.myidp.autoLogin.createSession': 'true',
                'idprovider.myidp.autoLogin.wsHeader': 'false',
                'idprovider.myidp.autoLogin.allowedAudience': 'audience1 audience2   audience3      audience4',
            }
        }
    });

    const configProvider = require('./configProvider');

    const config = configProvider.getIdProviderConfig('myidp');

    test.assertEquals('displayName', config.displayName);
    test.assertEquals('description', config.description);
    test.assertFalse(config.usePkce);
    test.assertEquals('custom_issuer', config.issuer);
    test.assertEquals('custom_authorizationUrl', config.authorizationUrl);
    test.assertEquals('custom_tokenUrl', config.tokenUrl);
    test.assertEquals('custom_userinfoUrl', config.userinfoUrl);
    test.assertEquals('custom_jwksUri', config.jwksUri);
    test.assertFalse(config.useUserinfo);
    test.assertEquals('post', config.method);
    test.assertEquals('name profile email nikname', config.scopes);
    test.assertEquals('clientId', config.clientId);
    test.assertEquals('clientSecret', config.clientSecret);
    test.assertJsonEquals(['group:myidp:default', 'group:myidp:dev'], config.defaultGroups);
    test.assertEquals('username', config.claimUsername);

    test.assertJsonEquals([{name: 'name0', url: 'url0'}, {name: 'name1', url: 'url1'}], config.additionalEndpoints);

    test.assertEquals('${nikname} - ${userinfo.name}', config.mappings.displayName);
    test.assertEquals('${email}', config.mappings.email);
    test.assertEquals('${userinfo.upn}', config.mappings.emailFallback);

    test.assertEquals('endSessionUrl', config.endSession.url);
    test.assertEquals('idTokenHintKey', config.endSession.idTokenHintKey);
    test.assertEquals('postLogoutRedirectUriKey', config.endSession.postLogoutRedirectUriKey);
    test.assertJsonEquals([{key: 'k0', value: 'v0'}, {key: 'k1', value: 'v1'}], config.endSession.additionalParameters);

    test.assertTrue(config.rules.forceEmailVerification);

    test.assertTrue(config.autoLogin.createUser);
    test.assertTrue(config.autoLogin.createSession);
    test.assertFalse(config.autoLogin.wsHeader);
    test.assertJsonEquals(['audience1', 'audience2', 'audience3', 'audience4'], config.autoLogin.allowedAudience);
};

exports.testDefaultConfigWithRequiredOptions = () => {
    mockWellKnownService();

    test.mock('/lib/configFile/services/getConfig', {
        getConfigOrEmpty: function () {
            return {
                'idprovider.myidp.oidcWellKnownEndpoint': 'wellKnownEndpoint',
            }
        }
    });

    const configProvider = require('./configProvider');

    const config = configProvider.getIdProviderConfig('myidp');

    test.assertEquals('myidp', config._idProviderName); // internal property

    test.assertNull(config.displayName);
    test.assertNull(config.description);
    test.assertTrue(config.usePkce);
    test.assertEquals('wellKnownEndpoint', config.oidcWellKnownEndpoint);
    test.assertEquals('issuer', config.issuer);
    test.assertEquals('authorizationUrl', config.authorizationUrl);
    test.assertEquals('tokenUrl', config.tokenUrl);
    test.assertEquals('userinfoUrl', config.userinfoUrl);
    test.assertEquals('jwksUri', config.jwksUri);
    test.assertTrue(config.useUserinfo);
    test.assertEquals('post', config.method);
    test.assertNull(config.clientId);
    test.assertNull(config.clientSecret);
    test.assertJsonEquals([], config.defaultGroups);

    test.assertEquals('profile email', config.scopes);
    test.assertEquals('sub', config.claimUsername);

    test.assertJsonEquals([], config.additionalEndpoints);

    test.assertEquals('${userinfo.preferred_username}', config.mappings.displayName);
    test.assertEquals('${userinfo.email}', config.mappings.email);
    test.assertEquals('${userinfo.preferred_username}', config.mappings.emailFallback);

    test.assertNull(config.endSession);

    test.assertFalse(config.rules.forceEmailVerification);

    test.assertTrue(config.autoLogin.createUser);
    test.assertFalse(config.autoLogin.createSession);
    test.assertFalse(config.autoLogin.wsHeader);
    test.assertJsonEquals([], config.autoLogin.allowedAudience);
};

exports.testValidateRequiredOptions = () => {
    const options = ['issuer', 'authorizationUrl', 'tokenUrl'];
    const idProviderName = 'myidp';
    const configuration = {};

    for (let i = 0; i < options.length; i++) {
        mockWellKnownService();

        test.mock('/lib/configFile/services/getConfig', {
            getConfigOrEmpty: function () {
                return configuration;
            }
        });

        const configProvider = require('./configProvider');

        try {
            configProvider.getIdProviderConfig(idProviderName);
        } catch (e) {
            test.assertEquals(`Missing config '${options[i]}' for ID Provider '${idProviderName}'.`, e);
        }

        configuration[`idprovider.${idProviderName}.${options[i]}`] = 'value';
    }
};

exports.testValidationOfAdditionalEndpoints = () => {
    const idProviderName = 'myidp';

    mockWellKnownService();

    test.mock('/lib/configFile/services/getConfig', {
        getConfigOrEmpty: function () {
            return {
                'idprovider.myidp.oidcWellKnownEndpoint': 'wellKnownEndpoint',

                'idprovider.myidp.additionalEndpoints.0.name': 'name0', // url is missing for this endpoint
                'idprovider.myidp.additionalEndpoints.1.name': 'name1',
                'idprovider.myidp.additionalEndpoints.1.url': 'url1',
            }
        }
    });

    const configProvider = require('./configProvider');

    try {
        configProvider.getIdProviderConfig(idProviderName);
    } catch (e) {
        test.assertEquals(`Invalid configuration of 'additionalEndpoints' for ID Provider '${idProviderName}'.`, e);
    }
};

exports.testValidationOfEndSessionAdditionalParameters = () => {
    const idProviderName = 'myidp';

    mockWellKnownService();

    test.mock('/lib/configFile/services/getConfig', {
        getConfigOrEmpty: function () {
            return {
                'idprovider.myidp.oidcWellKnownEndpoint': 'wellKnownEndpoint',

                'idprovider.myidp.endSession.url': 'logoutUrl',
                'idprovider.myidp.endSession.additionalParameters.0.key': 'k0',
                'idprovider.myidp.endSession.additionalParameters.0.value': 'v0',
                'idprovider.myidp.endSession.additionalParameters.1.value': 'v1',  // key is missing for this parameter
            }
        }
    });

    const configProvider = require('./configProvider');

    try {
        configProvider.getIdProviderConfig(idProviderName);
    } catch (e) {
        test.assertEquals(`Invalid configuration of 'endSession.additionalParameters' for ID Provider '${idProviderName}'.`, e);
    }
};

exports.testEmailFallbackCanBeDisabled = () => {
    // Blank is meaningful here, unlike the other mappings: it switches the fallback off rather than
    // falling through to the default.
    mockWellKnownService();

    test.mock('/lib/configFile/services/getConfig', {
        getConfigOrEmpty: function () {
            return {
                'idprovider.myidp.oidcWellKnownEndpoint': 'wellKnownEndpoint',
                'idprovider.myidp.mappings.emailFallback': '',
            }
        }
    });

    const configProvider = require('./configProvider');

    test.assertEquals('', configProvider.getIdProviderConfig('myidp').mappings.emailFallback);
};
