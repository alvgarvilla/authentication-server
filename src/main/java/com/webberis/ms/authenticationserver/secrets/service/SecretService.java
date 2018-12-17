package com.webberis.ms.authenticationserver.secrets.service;

import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;
import com.webberis.ms.authenticationserver.secrets.KeyPairFile;

public interface SecretService {
    
    void validateSecret(String secretName) throws SecretNotFoundException;
    
    void updateSecretByName(String secretName, KeyPairFile kpFile, String pubKeySecret) throws SecretNotFoundException;
    
    void done();
    
    void generateAndUpdateKey(String secretName, String alias, String keyName);
}
