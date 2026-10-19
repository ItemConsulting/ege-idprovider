package com.enonic.app.oidcidprovider.lib;

import org.junit.jupiter.api.Test;

import com.enonic.xp.testing.ScriptTestSupport;

public class LoginTest
    extends ScriptTestSupport
{
    @Test
    public void testKeepsStoredEmailWhenEmailClaimIsMissing()
    {
        runFunction( "/lib/login-test.js", "test_login_keepsStoredEmail_whenEmailClaimIsMissing" );
    }

    @Test
    public void testUpdatesEmailWhenEmailClaimIsPresent()
    {
        runFunction( "/lib/login-test.js", "test_login_updatesEmail_whenEmailClaimIsPresent" );
    }

    @Test
    public void testRefusesToCreateUserWhenEmailClaimIsMissing()
    {
        runFunction( "/lib/login-test.js", "test_login_refusesToCreateUser_whenEmailClaimIsMissing" );
    }

    @Test
    public void testFallsBackToPreferredUsernameWhenItIsAnAddress()
    {
        runFunction( "/lib/login-test.js", "test_login_fallsBackToPreferredUsername_whenItIsAnAddress" );
    }

    @Test
    public void testRejectsGuestUpnAsEmail()
    {
        runFunction( "/lib/login-test.js", "test_login_rejectsGuestUpnAsEmail" );
    }

    @Test
    public void testPrefersEmailClaimOverFallback()
    {
        runFunction( "/lib/login-test.js", "test_login_prefersEmailClaimOverFallback" );
    }

    @Test
    public void testRefusesWhenFallbackIsDisabled()
    {
        runFunction( "/lib/login-test.js", "test_login_refusesWhenFallbackIsDisabled" );
    }

    @Test
    public void testPrefersStoredEmailOverFallback()
    {
        runFunction( "/lib/login-test.js", "test_login_prefersStoredEmailOverFallback" );
    }

    @Test
    public void testHealsBlankedEmailFromFallback()
    {
        runFunction( "/lib/login-test.js", "test_login_healsBlankedEmailFromFallback" );
    }
}
