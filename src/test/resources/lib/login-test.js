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
            email: '${userinfo.email}',
            emailFallback: '${userinfo.preferred_username}'
        }
    };
}

/** Drives login() for a user that does not exist yet, and returns what createUser() was given. */
function loginNewUser(tokenClaims, config) {
    let created = null;

    setConfigMocks({getIdProviderConfig: config ? () => config : idProviderConfig});
    setAuthMocks({
        getPrincipal: () => null,
        modifyProfile: () => ({}),
        addMembers: () => {},
        createUser: (params) => {
            created = params;
            return {key: `user:${params.idProvider}:${params.name}`};
        },
        login: () => ({authenticated: true, user: {key: STORED_USER_KEY}})
    });

    let thrown = null;
    try {
        lib.login('access-token', tokenClaims, false);
    } catch (e) {
        thrown = e;
    }

    return {created: created, thrown: thrown};
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

exports.test_login_fallsBackToPreferredUsername_whenItIsAnAddress = () => {
    const result = loginNewUser({sub: 'abc', preferred_username: 'ola@monark-no.com'});

    test.assertTrue(result.created !== null);
    test.assertEquals('ola@monark-no.com', result.created.email);
};

exports.test_login_rejectsGuestUpnAsEmail = () => {
    // A B2B guest UPN contains '@' and would pass a naive check, but is not a deliverable address.
    const result = loginNewUser({sub: 'abc', preferred_username: 'hg_monark-no.com#EXT#@ege.onmicrosoft.com'});

    test.assertTrue(result.created === null);
    test.assertEquals('User can not be created without email', result.thrown);
};

exports.test_login_prefersEmailClaimOverFallback = () => {
    const result = loginNewUser({sub: 'abc', email: 'real@monark-no.com', preferred_username: 'upn@monark-no.com'});

    test.assertEquals('real@monark-no.com', result.created.email);
};

exports.test_login_refusesWhenFallbackIsDisabled = () => {
    const config = idProviderConfig();
    config.mappings.emailFallback = '';

    const result = loginNewUser({sub: 'abc', preferred_username: 'ola@monark-no.com'}, config);

    test.assertEquals('User can not be created without email', result.thrown);
};

exports.test_login_prefersStoredEmailOverFallback = () => {
    // The stored address came from a real claim and has matched downstream; a UPN that merely looks
    // like an address can only preserve that or silently break it.
    const written = loginExistingUser(
        {key: STORED_USER_KEY, displayName: 'Old Name', email: 'ola@monark-no.com'},
        {sub: 'abc', preferred_username: 'moved@monark-no.com'});

    test.assertTrue(written !== null);
    test.assertEquals('ola@monark-no.com', written.email);
};

exports.test_login_healsBlankedEmailFromFallback = () => {
    // Users emptied by the missing guard in updateUserData get an address back on next login.
    const written = loginExistingUser(
        {key: STORED_USER_KEY, displayName: 'Old Name', email: ''},
        {sub: 'abc', preferred_username: 'ola@monark-no.com'});

    test.assertTrue(written !== null);
    test.assertEquals('ola@monark-no.com', written.email);
};

