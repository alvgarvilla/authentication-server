package com.webberis.ms.authenticationserver.secrets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.webberis.ms.authenticationserver.config.JwtSignerProperty;
import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;
import com.webberis.ms.authenticationserver.secrets.service.SecretService;
import com.webberis.ms.authenticationserver.secrets.service.SecretServiceFactory;

/**
 * Cron Job that validates every defined time the KeyStore for signing JWT tokens.
 *  
 * @author alvgarvilla
 *
 */
@Component
public class RotateKeyStore {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RotateKeyStore.class);
    
    @Value("spring.profiles.active")
    String profile;
    
	@Autowired
	private JwtSignerProperty jwtSignerProperties;    
    
    /**
     * Every hour...
     * 
     * 1. First we find the Secret by name and we validate it
     * 2. In case it does not exist, it failes
     * 3. In case the keySecret is not valid, we regenerate it.
     */
    @Scheduled(fixedRate = 3600000)
    public void verifyJwtKeyRotation() {
        LOGGER.info("KeyRotation verification");
        SecretService secretService = SecretServiceFactory.getInstance(profile, jwtSignerProperties.getKsAlias());
        try {
            secretService.validateSecrets(jwtSignerProperties.getK8sKsSecretName(), jwtSignerProperties.getK8sPubSecretName());
        } catch (SecretNotFoundException e) {
            LOGGER.error("----------------- SECRET NOT FOUND --------------");
        } finally {
            secretService.done();
        }
    }

}
