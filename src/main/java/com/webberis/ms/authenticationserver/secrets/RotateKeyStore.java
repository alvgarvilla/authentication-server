package com.webberis.ms.authenticationserver.secrets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;
import com.webberis.ms.authenticationserver.secrets.service.SecretService;
import com.webberis.ms.authenticationserver.secrets.service.SecretServiceFactory;

/**
 * Cron Job that validates every defined time the KeyStore for signing JWT tokens.
 *  
 * @author GarcAl01
 *
 */
@Component
@ConditionalOnProperty(prefix = "security", name = "jwtSigner.rotateKey", matchIfMissing = false)
public class RotateKeyStore {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RotateKeyStore.class);
    
    @Value("spring.profiles.active")
    String profile;
    
    @Value("security.jwtSigner.k8sKsSecretName")
    String ksSecretName;
    
    @Value("security.jwtSigner.k8sPubSecretName")
    String pubSecretName;
    
    @Value("security.jwtSigner.ksAlias")
    String ksAlias;
    
    /**
     * 1. First we find the Secret by name and we validate it
     * 2. In case it does not exist, it failes
     * 3. In case the keySecret is not valid, we regenerate it.
     */
    @Scheduled(fixedRate = 360000)
    public void verifyJwtKeyRotation() {
        LOGGER.info("KeyRotation verification");
        SecretService secretService = SecretServiceFactory.getInstance(profile, ksAlias);
        try {
            secretService.validateSecrets(ksSecretName, pubSecretName);
        } catch (SecretNotFoundException e) {
            LOGGER.error("----------------- SECRET NOT FOUND --------------");
        } finally {
            secretService.done();
        }
    }

}
