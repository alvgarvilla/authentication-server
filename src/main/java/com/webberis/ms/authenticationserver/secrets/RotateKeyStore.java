package com.webberis.ms.authenticationserver.secrets;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.webberis.ms.authenticationserver.exception.KeySecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;

import io.fabric8.kubernetes.api.model.Secret;


@Component
@Profile("kubernetes")
public class RotateKeyStore {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RotateKeyStore.class);
    
    @Autowired
    Environment env;
    
    private KeyPairKubernetesSecret jxtK8sSecret;
    private Integer week;
    private Integer year;
    
    @Scheduled(fixedRate = 360000)
    public void verifyJwtKeyRotation() {
        LOGGER.info("KeyRotation verification");
        this.initParams();
        try {
            Secret secret = this.jxtK8sSecret.secretK8sJwt();
            this.validateActualWeek(secret);
            this.validateNextWeek(secret);
        } catch (SecretNotFoundException e) {
            LOGGER.error("----------------- SECRET NOT FOUND --------------");
        } finally {
            this.jxtK8sSecret.done();
        }
    }
    
    private void initParams() {
        this.jxtK8sSecret = this.generateJwtKubernetesSecret(env.getProperty("security.jwt-signer.k8s-ks-secret-name"));
        
        Date now = new Date();
        this.week = Integer.valueOf(new SimpleDateFormat("w").format(now));
        this.year = Integer.valueOf(new SimpleDateFormat("y").format(now));
    }
    
    private void validateActualWeek(Secret secret) {
        try {
            KeyPairKubernetesSecret.validateData(secret.getData(), this.week, this.year);
        } catch (KeySecretNotFoundException e) {
            LOGGER.error("Actual week key not found. Generating it");
            this.generateAndUpdateKey(secret, this.week, this.year);
        } 
    }
    
    private void validateNextWeek(Secret secret) {
        try {
            KeyPairKubernetesSecret.validateData(secret.getData(), this.week + 1, this.year); 
        } catch (KeySecretNotFoundException e) {
            LOGGER.error("Next week key not found. Generating it");
            KeyPairKubernetesSecret.cleanData(secret.getData(), this.week - 1, this.year);
            this.generateAndUpdateKey(secret, this.week + 1, this.year);
        }
    }
    
    private void generateAndUpdateKey(Secret secret, Integer week, Integer year) {
        KeyPairFile kpFile = new KeyPairFile(env.getProperty("security.jwtSigner.ksAlias"));
        String pubKeySecret = env.getProperty("security.jwtSigner.k8sPubSecretName");
        this.jxtK8sSecret.updateSecret(secret, kpFile, pubKeySecret, week, year);
    }
    
    public KeyPairKubernetesSecret generateJwtKubernetesSecret(String secret) {
        return new KeyPairKubernetesSecret(secret);
    }
}
