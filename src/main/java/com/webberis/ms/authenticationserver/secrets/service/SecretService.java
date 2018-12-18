package com.webberis.ms.authenticationserver.secrets.service;

import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;

public interface SecretService {
    
    /**
     * Validate the secret stored
     * 
     * @param secretName
     * @throws SecretNotFoundException
     */
    void validateSecret(String secretName) throws SecretNotFoundException;
    
    void done();
    
    void cleanAndGenerateSecret(String ksSecretName, String publicSecretName, String alias);
}
