const test = require('/lib/xp/testing');
const testUtils = require('/testUtils');

const setConfigMocks = testUtils.mockAndGetUpdaterFunc(
    "/lib/config.js",
    {
        getIdProviderConfig: null
    }
);
const setAuthMocks = testUtils.mockAndGetUpdaterFunc(
    "/lib/xp/auth.js",
    {
        getPrincipal: null,
        modifyProfile: null,
        modifyUser: null,
        createUser: null,
        addMembers: null,
        login: null
    }
);

// These never vary between the cases below, so they are set once:
testUtils.mockAndGetUpdaterFunc("/lib/xp/portal.js", {getIdProviderKey: () => 'myidp'});
testUtils.mockAndGetUpdaterFunc("/lib/xp/common.js", {sanitize: (value) => value});
testUtils.mockAndGetUpdaterFunc("/lib/context.js", {runAsSu: (callback) => callback()});
testUtils.mockAndGetUpdaterFunc("/lib/oidc.js", {requestOAuth2: null, mergeClaims: null});

// Require login AFTER mocking the libs it binds at load time:
const lib = require('/lib/login');


/////////////////////////////////////////////

const STORED_USER_KEY = 'user:myidp:abc';

// useUserinfo is false and there are no additional endpoints, so resolveClaims() reads the token
// claims only and never reaches the mocked oidc lib.
function idProviderConfig() {
    return {
        _idProviderName: 'myidp',
        claimUsername: 'sub',
        useUserinfo: false,
        userinfoUrl: null,
        additionalEndpoints: [],
        defaultGroups: [],
        rules: {
            forceEmailVerification: false
        },
        mappings: {
            displayName: '${userinfo.preferred_username}',
            email: '${userinfo.email}'
        }
    };
}

/**
 * Drives login() for a user that already exists, and returns the record updateUserData() wrote -
 * or null when it decided there was nothing to write.
 */
function loginExistingUser(storedUser, tokenClaims) {
    let written = null;

    setConfigMocks({getIdProviderConfig: idProviderConfig});
    setAuthMocks({
        getPrincipal: () => storedUser,
        modifyProfile: () => ({}),
        modifyUser: (params) => {
            written = params.editor({displayName: storedUser.displayName, email: storedUser.email});
            return written;
        },
        login: () => ({authenticated: true, user: storedUser})
    });

    lib.login('access-token', tokenClaims, false);

    return written;
}

exports.test_login_keepsStoredEmail_whenEmailClaimIsMissing = () => {
    const written = loginExistingUser(
        {key: STORED_USER_KEY, displayName: 'Old Name', email: 'ola@example.com'},
        {sub: 'abc', preferred_username: 'New Name'});

    // The display name changed, so the user is written either way. The point is that the address
    // survives that write instead of being replaced by the '' a missing claim resolves to.
    test.assertTrue(written !== null);
    test.assertEquals('New Name', written.displayName);
    test.assertEquals('ola@example.com', written.email);
};

exports.test_login_updatesEmail_whenEmailClaimIsPresent = () => {
    const written = loginExistingUser(
        {key: STORED_USER_KEY, displayName: 'Old Name', email: 'old@example.com'},
        {sub: 'abc', preferred_username: 'New Name', email: 'new@example.com'});

    test.assertTrue(written !== null);
    test.assertEquals('new@example.com', written.email);
};

exports.test_login_refusesToCreateUser_whenEmailClaimIsMissing = () => {
    setConfigMocks({getIdProviderConfig: idProviderConfig});
    setAuthMocks({
        getPrincipal: () => null,
        createUser: () => {
            throw 'createUser should not be reached without an email';
        }
    });

    let thrown = null;
    try {
        lib.login('access-token', {sub: 'abc', preferred_username: 'New Name'}, false);
    } catch (e) {
        thrown = e;
    }

    test.assertEquals('User can not be created without email', thrown);
};
