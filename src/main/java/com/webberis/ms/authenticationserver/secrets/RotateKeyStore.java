package com.webberis.ms.authenticationserver.secrets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.webberis.ms.authenticationserver.exception.KeySecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;
import com.webberis.ms.authenticationserver.secrets.service.SecretService;
import com.webberis.ms.authenticationserver.secrets.service.SecretServiceFactory;

@Component
@ConditionalOnProperty(prefix = "security", name = "jwtSigner.rotateKey", matchIfMissing = false)
public class RotateKeyStore {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RotateKeyStore.class);
    
    @Autowired
    Environment env;
    
    @Value("security.jwtSigner.k8sKsSecretName")
    String secretName;
    
    private SecretService secretService;
    
    public RotateKeyStore() {
        this.secretService = SecretServiceFactory.getInstance(env.getProperty("spring.profiles.active"));
    }
    
    @Scheduled(fixedRate = 360000)
    public void verifyJwtKeyRotation() {
        LOGGER.info("KeyRotation verification");
        try {
            this.secretService.validateSecret(secretName);
        } catch (KeySecretNotFoundException e) {
            LOGGER.error(e.getMessage());
            generateAndUpdateKey();
        } catch (SecretNotFoundException e) {
            LOGGER.error("----------------- SECRET NOT FOUND --------------");
        } finally {
            this.secretService.done();
        }
    }
    
    private void generateAndUpdateKey() {
        KeyPairFile kpFile = new KeyPairFile(env.getProperty("security.jwtSigner.ksAlias"));
        String pubKeySecret = env.getProperty("security.jwtSigner.k8sPubSecretName");
        this.secretService.updateSecretByName(secretName, kpFile, pubKeySecret);
    }
    
    public KeyPairKubernetesSecret generateJwtKubernetesSecret(String secret) {
        return new KeyPairKubernetesSecret(secret);
    }
}
