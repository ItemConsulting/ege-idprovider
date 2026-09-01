const authLib = require('/lib/xp/auth');
const contextLib = require('/lib/context');
const configLib = require('/lib/config');
const commonLib = require('/lib/xp/common');
const portalLib = require('/lib/xp/portal');
const preconditions = require('/lib/preconditions');
const oidcLib = require('./oidc');

const regExp = /\$\{([^\}]+)\}/g;

function login(token, tokenClaims, isAutoLogin) {
    const idProviderKey = portalLib.getIdProviderKey();
    const idProviderConfig = configLib.getIdProviderConfig();
    const userName = commonLib.sanitize(preconditions.checkParameter(tokenClaims, idProviderConfig.claimUsername));
    const principalKey = `user:${idProviderKey}:${userName}`;
    const user = contextLib.runAsSu(() => authLib.getPrincipal(principalKey));

    let claims = isAutoLogin? tokenClaims : resolveClaims(idProviderConfig, token, tokenClaims);
    let wasUserCreated = false;
    if (!user) {
        if (!isAutoLogin || idProviderConfig.autoLogin.createUser) {
            if (isAutoLogin) {
                claims = resolveClaims(idProviderConfig, token, tokenClaims);
            }
            doCreateUser(idProviderConfig, claims, userName, isAutoLogin);
            wasUserCreated = true;
        } else if (isAutoLogin) {
            throwAutoLoginFailedError(`Auto login failed for user '${userName}'. User does not exist`);
        }
    }

    if (wasUserCreated || !isAutoLogin) {
        saveClaims(claims, principalKey);
    }

    if (!wasUserCreated && !isAutoLogin) {
        updateUserData(claims, idProviderConfig, user);
    }

    return doLogin(idProviderConfig, userName, isAutoLogin);
}

function getClaim(claims, claimKey) {
    const claimKeys = claimKey.split('.');

    let currentClaimObject = claims;
    let claim;
    for (const claimKey of claimKeys) {
        currentClaimObject = currentClaimObject[claimKey];
        if (currentClaimObject == null) {
            log.warning(`Claim [${claimKey}] missing`);
            return '';
        }
        claim = currentClaimObject;
    }
    return claim || '';
}

/**
 * Lists the claim names received, grouped by scope, for diagnostics.
 *
 * Names only, never values: the values are personal data, and it is the names that answer the
 * question a missing claim actually raises - whether the authorization server sent nothing usable,
 * or sent the value under a name the configured mapping does not read.
 */
function describeClaimNames(claims) {
    return Object.keys(claims)
        .sort()
        .map(scope => {
            const scopeClaims = claims[scope];
            const names = scopeClaims && typeof scopeClaims === 'object' ? Object.keys(scopeClaims).sort() : [];
            return `${scope}: [${names.join(', ')}]`;
        })
        .join(' ');
}

function removeNonSupportedKeys(claims) {
    if (typeof claims !== 'object' || claims === null) {
        return claims;
    }

    if (Array.isArray(claims)) {
        return claims.map(removeNonSupportedKeys);
    }

    const newClaims = {};

    for (const key in claims) {
        if (claims.hasOwnProperty(key) && !(key.indexOf('.') !== -1 || key.indexOf('[') !== -1 || key.indexOf(']') !== -1)) {
            newClaims[key] = removeNonSupportedKeys(claims[key]);
        }
    }

    return newClaims;
}

function saveClaims(claims, principalKey) {
    const profile = contextLib.runAsSu(() => authLib.modifyProfile({
        key: principalKey,
        scope: 'oidc',
        editor: () => removeNonSupportedKeys(claims)
    }));

    log.debug(`Modified profile of [${principalKey}]: ${JSON.stringify(profile)}`);
}

function doLogin(idProviderConfig, userName, isAutoLogin) {
    const idProviderKey = idProviderConfig._idProviderName;
    const principalKey = `user:${idProviderKey}:${userName}`;

    const loginParams = {
        user: userName,
        idProvider: idProviderKey,
        skipAuth: true
    };

    if (isAutoLogin) {
        loginParams.scope = idProviderConfig.autoLogin.createSession ? 'SESSION' : 'REQUEST';
    }

    //Logs in the user
    const loginResult = authLib.login(loginParams);
    if (loginResult.authenticated) {
        log.debug(`Logged in user [${principalKey}]`);
    } else {
        if (isAutoLogin) {
            throwAutoLoginFailedError(`Auto login failed for user [${principalKey}]`);
        }
        throw `Error while logging user [${principalKey}]`;
    }
    return loginResult;
}

function doCreateUser(idProviderConfig, claims, userName, isAutoLogin) {
    const userinfoClaims = claims.userinfo;

    if (idProviderConfig.rules.forceEmailVerification) {
        if (userinfoClaims.email_verified !== true) {
            if (isAutoLogin) {
                throwAutoLoginFailedError(`Auto login failed for user '${userName}'. Email must be verified`);
            }
            throw 'Email must be verified';
        }
    }

    const email = resolveEmail(claims, idProviderConfig);
    const displayName = resolveDisplayName(claims, idProviderConfig) || email;

    if (!email) {
        // The thrown message can reach the browser, so the diagnosis goes to the log instead.
        // Without this the log names neither the user nor what arrived, and identifying who failed
        // means correlating timestamps against the authorization server's own sign-in logs.
        log.warning(`No email for user '${userName}' in [${idProviderConfig._idProviderName}] ` +
                    `resolved from mapping [${idProviderConfig.mappings.email}]. ` +
                    `Claims received: ${describeClaimNames(claims)}`);

        if (isAutoLogin) {
            throwAutoLoginFailedError(`Auto login failed for user '${userName}'. User can not be created without email.`);
        }
        throw 'User can not be created without email';
    }

    let user;
    try {
        user = contextLib.runAsSu(() => authLib.createUser({
            idProvider: idProviderConfig._idProviderName,
            name: userName,
            displayName: displayName,
            email: email
        }));
        log.info(`User [${user.key}] created in ID Provider [${idProviderConfig._idProviderName}]`);
    } catch (e) {
        if (`${e}`.startsWith('com.enonic.xp.security.PrincipalAlreadyExistsException')) {
            const principalKey = `user:${idProviderConfig._idProviderName}:${userName}`
            user = contextLib.runAsSu(() => authLib.getPrincipal(principalKey));
        } else {
            throw `User '${userName}' could not be provided: ${e}`;
        }
    }

    if (user) {
        contextLib.runAsSu(() => {
            idProviderConfig.defaultGroups.forEach(function (defaultGroup) {
                authLib.addMembers(defaultGroup, [user.key]);
                log.debug(`User [${user.key}] added to group [${defaultGroup}]`);
            });
        });
    }
}

function resolveClaims(idProviderConfig, accessToken, tokenClaims) {
    const claims = {
        userinfo: tokenClaims
    };

    if (idProviderConfig.userinfoUrl && idProviderConfig.useUserinfo) {
        const userinfoClaims = oidcLib.requestOAuth2({
            url: idProviderConfig.userinfoUrl,
            accessToken: accessToken,
        });

        if (tokenClaims.sub !== userinfoClaims.sub) {
            throw `Invalid sub in user info : ${userinfoClaims.sub}`;
        }

        claims.userinfo = oidcLib.mergeClaims(claims.userinfo, userinfoClaims);
    }

    idProviderConfig.additionalEndpoints.forEach(additionalEndpoint => {
        const additionalClaims = oidcLib.requestOAuth2({
            url: additionalEndpoint.url,
            accessToken: accessToken
        });
        log.debug(`OAuth2 endpoint [${additionalEndpoint.name}] claims: ${JSON.stringify(additionalClaims)}`);
        claims[additionalEndpoint.name] = oidcLib.mergeClaims(claims[additionalEndpoint.name] || {}, additionalClaims);
    });

    return claims;
}

function throwAutoLoginFailedError(message) {
    const error = Error(message);
    error.name = 'AutoLoginFailedError';

    throw error;
}

function resolveEmail(claims, idProviderConfig) {
    return idProviderConfig.mappings.email.replace(regExp, (match, claimKey) => getClaim(claims, claimKey)) ||
           claims.userinfo.email;
}

function resolveDisplayName(claims, idProviderConfig) {
    const userinfoClaims = claims.userinfo;
    return idProviderConfig.mappings.displayName.replace(regExp,
        (match, claimKey) => getClaim(claims, claimKey)) || userinfoClaims.preferred_username || userinfoClaims.name || userinfoClaims.sub;
}

function updateUserData(claims, idProviderConfig, user) {
    const email = resolveEmail(claims, idProviderConfig);
    const displayName = resolveDisplayName(claims, idProviderConfig) || email;

    // resolveEmail() returns '' for a missing claim, and writing that through erased an address the
    // user already had. Creating a user without one is refused outright in doCreateUser(), so an
    // existing user keeps what is stored rather than being silently emptied - a state that is hard
    // to trace back here, because it surfaces later as an unrelated lookup failing by email.
    const nextEmail = email || user.email;

    if (!email) {
        log.warning(`No email for user [${user.key}] resolved from mapping [${idProviderConfig.mappings.email}], ` +
                    `keeping the stored address. Claims received: ${describeClaimNames(claims)}`);
    }

    if (user.displayName !== displayName || user.email !== nextEmail) {
        contextLib.runAsSu(() => authLib.modifyUser({
            key: user.key,
            editor: function (c) {
                c.displayName = displayName;
                c.email = nextEmail;
                return c;
            }
        }));

        log.debug(`User [${user.key}] updated with displayName [${displayName}] and email [${nextEmail}]`);
    }
}

exports.login = login;
