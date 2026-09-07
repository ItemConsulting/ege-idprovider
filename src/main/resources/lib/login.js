const authLib = require('/lib/xp/auth');
const contextLib = require('/lib/context');
const configLib = require('/lib/config');
const commonLib = require('/lib/xp/common');
const portalLib = require('/lib/xp/portal');
const preconditions = require('/lib/preconditions');
const oidcLib = require('./oidc');

const regExp = /\$\{([^\}]+)\}/g;

// Deliberately strict, and `#` is excluded on purpose: it is what disqualifies a guest UPN.
const EMAIL_PATTERN = /^[^\s@#]+@[^\s@#]+\.[^\s@#]+$/;

function login(token, tokenClaims, isAutoLogin) {
    const idProviderKey = portalLib.getIdProviderKey();
    const idProviderConfig = configLib.getIdProviderConfig();
    const userName = commonLib.sanitize(preconditions.checkParameter(tokenClaims, idProviderConfig.claimUsername));
    const principalKey = `user:${idProviderKey}:${userName}`;
    const user = contextLib.runAsSu(() => authLib.getPrincipal(principalKey));

    let claims = isAutoLogin? tokenClaims : resolveClaims(idProviderConfig, token, tokenClaims);
    let wasUserCreated = false;
    let emailSource = 'not resolved';
    if (!user) {
        if (!isAutoLogin || idProviderConfig.autoLogin.createUser) {
            if (isAutoLogin) {
                claims = resolveClaims(idProviderConfig, token, tokenClaims);
            }
            emailSource = doCreateUser(idProviderConfig, claims, userName, isAutoLogin);
            wasUserCreated = true;
        } else if (isAutoLogin) {
            throwAutoLoginFailedError(`Auto login failed for user '${userName}'. User does not exist`);
        }
    }

    if (wasUserCreated || !isAutoLogin) {
        saveClaims(claims, principalKey);
    }

    if (!wasUserCreated && !isAutoLogin) {
        emailSource = updateUserData(claims, idProviderConfig, user);
    }

    const loginResult = doLogin(idProviderConfig, userName, isAutoLogin);

    // Interactive logins only. Auto-login runs per request, so one entry per call would bury the
    // line that says a person actually signed in. The source is the point of logging this at all:
    // once an address is stored on the user, one that arrived by fallback is indistinguishable
    // from one that arrived in a claim, so without it there is no way to tell from the outside
    // whether the fallback is carrying a tenant or has simply never fired.
    if (!isAutoLogin) {
        const userState = wasUserCreated ? 'user created' : 'existing user';
        log.info(`Login succeeded for [${principalKey}] - ${userState}, email from [${emailSource}]`);
    }

    return loginResult;
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

    // A user being created has nothing stored yet, so the middle step of the precedence is empty.
    const resolved = resolveEmailWithSource(claims, idProviderConfig, null);
    const email = resolved.email;
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

    return resolved.source;
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

/**
 * Second chance at an address when the configured mapping yields nothing.
 *
 * Entra only emits an `email` claim when the directory holds a value for it; where it does not, the
 * address still usually arrives as the UPN. Taking it is worth doing, but only once it actually
 * looks like an address - a B2B guest UPN reads `someone_example.com#EXT#@tenant.onmicrosoft.com`,
 * and storing that as the user's email would satisfy every check here while matching nothing
 * downstream. Failing loudly is better than a plausible address that is quietly wrong.
 */
function resolveEmailFallback(claims, idProviderConfig) {
    const mapping = idProviderConfig.mappings.emailFallback;

    if (!mapping) {
        return '';
    }

    const candidate = mapping.replace(regExp, (match, claimKey) => getClaim(claims, claimKey)).trim();

    if (!candidate) {
        return '';
    }

    if (!EMAIL_PATTERN.test(candidate)) {
        log.warning(`Email fallback [${mapping}] resolved to [${candidate}], which is not an email address. Ignoring it.`);
        return '';
    }

    return candidate;
}

/**
 * The address, plus where it came from.
 *
 * Both callers already shared one precedence order - the claim, then whatever is already stored,
 * then the fallback - and this puts it in a single place rather than open-coding it twice. The
 * source it returns is what the caller logs; the address itself is not logged, since the claim
 * names are what diagnose a missing one and the value is personal data.
 */
function resolveEmailWithSource(claims, idProviderConfig, storedEmail) {
    const claimEmail = resolveEmail(claims, idProviderConfig);
    if (claimEmail) {
        return {email: claimEmail, source: 'claim'};
    }

    if (storedEmail) {
        return {email: storedEmail, source: 'stored'};
    }

    const fallbackEmail = resolveEmailFallback(claims, idProviderConfig);
    if (fallbackEmail) {
        return {email: fallbackEmail, source: 'fallback'};
    }

    return {email: '', source: 'none'};
}

function resolveDisplayName(claims, idProviderConfig) {
    const userinfoClaims = claims.userinfo;
    return idProviderConfig.mappings.displayName.replace(regExp,
        (match, claimKey) => getClaim(claims, claimKey)) || userinfoClaims.preferred_username || userinfoClaims.name || userinfoClaims.sub;
}

/**
 * Precedence for an existing user: the claim, then the address already stored, then the fallback.
 *
 * The stored address outranks the fallback deliberately. It got there from a real `email` claim and
 * has presumably already matched downstream, so replacing it with a UPN that merely looks like an
 * address can only preserve that match or silently break it - and a wrong-but-valid address is worse
 * than none, because an absent one fails immediately and visibly while a wrong one just stops
 * matching. Only a user with nothing stored falls through to the fallback, which also heals the ones
 * emptied by the missing guard this replaced.
 */
function updateUserData(claims, idProviderConfig, user) {
    const resolved = resolveEmailWithSource(claims, idProviderConfig, user.email);
    const email = resolved.email;
    const displayName = resolveDisplayName(claims, idProviderConfig) || email;

    if (resolved.source !== 'claim') {
        let outcome;
        if (resolved.source === 'stored') {
            outcome = 'keeping the stored address';
        } else if (resolved.source === 'fallback') {
            outcome = 'using the fallback';
        } else {
            outcome = 'no address available';
        }

        log.warning(`No email for user [${user.key}] resolved from mapping [${idProviderConfig.mappings.email}] - ` +
                    `${outcome}. Claims received: ${describeClaimNames(claims)}`);
    }

    if (user.displayName !== displayName || user.email !== email) {
        contextLib.runAsSu(() => authLib.modifyUser({
            key: user.key,
            editor: function (c) {
                c.displayName = displayName;
                c.email = email;
                return c;
            }
        }));

        log.debug(`User [${user.key}] updated with displayName [${displayName}] and email [${email}]`);
    }

    return resolved.source;
}

exports.login = login;
