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
}
