package com.enonic.app.oidcidprovider.handler;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;

import com.enonic.app.oidcidprovider.jwt.RSAAlgorithmProvider;

// The pid must track the application name, so that editing the app's .cfg reactivates this component
// and clears CACHE below. It was left behind when the app was renamed, which meant config edits were
// parsed into a cache that nothing ever invalidated - they took effect only on restart.
@Component(immediate = true, service = IdProviderConfigService.class, configurationPid = "no.ege.oidcidprovider")
public class IdProviderConfigService
{
    private static final ConcurrentMap<String, IdProviderManager> CACHE = new ConcurrentHashMap<>();

    @Activate
    public void activate()
    {
        CACHE.clear();
    }

    public void storeConfig( final String key, final Map<String, Object> config )
    {
        final IdProviderManager idProviderManager = new IdProviderManager( config );
        CACHE.put( key, idProviderManager );
    }

    public Map<String, Object> getConfig( final String key )
    {
        final IdProviderManager idProviderManager = CACHE.get( key );
        return idProviderManager != null ? idProviderManager.getIdProviderConfig() : null;
    }

    public RSAAlgorithmProvider getAlgorithmProvider( final String key )
    {
        final IdProviderManager idProviderManager = CACHE.get( key );
        return idProviderManager != null ? idProviderManager.getAlgorithmProvider() : null;
    }
}
