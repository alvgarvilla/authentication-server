package com.webberis.ms.authenticationserver.secrets.service;

import com.webberis.ms.authenticationserver.exception.WebberisGlobalException;
import com.webberis.ms.authenticationserver.secrets.service.impl.KubernetesSecretService;

/**
 * SecretService factory that creates the proper instance depending on the service name.
 * 
 * @author Alvaro Garcia
 *
 */
public class SecretServiceFactory {
    
    public static SecretService getInstance(String profile, String aliasName) {
        if (profile.equalsIgnoreCase("kubernetes")) {
            return new KubernetesSecretService(aliasName);
        } else {
            throw new WebberisGlobalException("Invalid secret service name -> " + profile);
        }
    }

}
