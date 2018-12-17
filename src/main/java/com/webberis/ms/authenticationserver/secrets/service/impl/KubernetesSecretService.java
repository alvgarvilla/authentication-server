package com.webberis.ms.authenticationserver.secrets.service.impl;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import com.webberis.ms.authenticationserver.exception.KeySecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.WebberisGlobalException;
import com.webberis.ms.authenticationserver.secrets.KeyPairFile;
import com.webberis.ms.authenticationserver.secrets.KeyPairKubernetesSecret;
import com.webberis.ms.authenticationserver.secrets.service.SecretServiceAbstract;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.AutoAdaptableKubernetesClient;

public class KubernetesSecretService extends SecretServiceAbstract {
    
    private AutoAdaptableKubernetesClient adp;
    private Integer week;
    private Integer year;
    
    public KubernetesSecretService() {
        this.adp = new AutoAdaptableKubernetesClient();
        Date now = new Date();
        this.week = Integer.valueOf(new SimpleDateFormat("w").format(now));
        this.year = Integer.valueOf(new SimpleDateFormat("y").format(now));
    }

    @Override
    public void validateSecret(String secretName) throws SecretNotFoundException {
        Secret secret = this.byName(secretName).orElseThrow(() -> new SecretNotFoundException());
        if (secret.getData() == null) {
            secret.setData(new HashMap<>());
        }
        this.validateActualWeek(secret);
        this.validateNextWeek(secret);
    }
    
    @Override
    public void updateSecretByName(String secretName, KeyPairFile kpFile, String pubKeySecret, Integer week, Integer year) {
        Secret secret = this.byName(secretName).orElseThrow(() -> new SecretNotFoundException());
        try {
            String keyStoreValue = encodeFile(kpFile.getJksFile());
            secret.getData().put(jksFormat(week, year), keyStoreValue);
            
            String passValue = encodePassword(kpFile.getPassword());
            secret.getData().put(passFormat(week, year), passValue);
            
            Secret pubSecret = this.byName(pubKeySecret).get();
            secretPublicKey(pubSecret, kpFile, week, year);
            
            this.adp.secrets().createOrReplace(pubSecret);
            this.adp.secrets().createOrReplace(secret);
        } catch (Exception e) {
            throw new WebberisGlobalException("Error while updating the keystore secret -> " + e.getMessage(), e);
        }
    }
    
    @Override
    public void done() {
        this.adp.close();
    }
    
    @Override
    public void generateAndUpdateKey(String secretName, String alias, String keyName) {
        KeyPairFile kpFile = new KeyPairFile(alias);
        this.updateSecretByName(secretName, kpFile, keyName, this.week , this.year);
    }
    
    /**
     * Returns Secret by name
     * @param name
     * @return
     */
    private Optional<Secret> byName(String name) {
        return this.secrets().stream()
            .filter(s -> s.getMetadata().getName().equalsIgnoreCase(name))
            .findFirst();
    }
    
    /**
     * Returns list of Kubernetes secrets
     * 
     * @return
     */
    private List<Secret> secrets() {
        return this.adp.secrets().list().getItems();
    }
    
    private void validateActualWeek(Secret secret) {
        try {
            KeyPairKubernetesSecret.validateData(secret.getData(), this.week, this.year);
        } catch (KeySecretNotFoundException e) {
            throw new KeySecretNotFoundException("Actual week key not found. Generating it");
        } 
    }
    
    private void validateNextWeek(Secret secret) {
        try {
            KeyPairKubernetesSecret.validateData(secret.getData(), this.week + 1, this.year); 
        } catch (KeySecretNotFoundException e) {
            cleanData(secret.getData(), this.week - 1, this.year);
            KeyPairFile kpFile = new KeyPairFile(alias);
            //this.generateAndUpdateKey(secret, this.week + 1, this.year);
            throw new KeySecretNotFoundException("Next week key not found. Generating it");
            //KeyPairKubernetesSecret.cleanData(secret.getData(), this.week - 1, this.year);
        }
    }
    
    protected static void secretPublicKey(Secret pubSecret, KeyPairFile kpFile, Integer week, Integer year) throws Exception {
        if (pubSecret.getData() == null) {
            pubSecret.setData(new HashMap<>());
        }
        String pubKeyContent = encodeFile(kpFile.getPublicKey());
        pubSecret.getData().put(pubFormat(week, year), pubKeyContent);
    }
    
    private static void cleanData() {
        
    }

}
