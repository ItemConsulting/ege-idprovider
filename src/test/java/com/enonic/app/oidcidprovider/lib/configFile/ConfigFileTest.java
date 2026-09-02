package com.enonic.app.oidcidprovider.lib.configFile;

import org.junit.jupiter.api.Test;

import com.enonic.xp.testing.ScriptTestSupport;

public class ConfigFileTest
    extends ScriptTestSupport
{
    @Test
    public void testConfigFile()
    {
        runFunction( "/lib/configFile/configIdProvider-test.js", "testValidConfig" );
    }

    @Test
    public void testConfigFileDefault()
    {
        runFunction( "/lib/configFile/configIdProvider-test.js", "testDefaultConfigWithRequiredOptions" );
    }

    @Test
    public void testValidateRequiredOptions()
    {
        runFunction( "/lib/configFile/configIdProvider-test.js", "testValidateRequiredOptions" );
    }

    @Test
    public void testValidationOfAdditionalEndpoints()
    {
        runFunction( "/lib/configFile/configIdProvider-test.js", "testValidationOfAdditionalEndpoints" );
    }

    @Test
    public void testValidationOfEndSessionAdditionalParameters()
    {
        runFunction( "/lib/configFile/configIdProvider-test.js", "testValidationOfEndSessionAdditionalParameters" );
    }

    @Test
    public void testEmailFallbackCanBeDisabled()
    {
        runFunction( "/lib/configFile/configIdProvider-test.js", "testEmailFallbackCanBeDisabled" );
    }
}
