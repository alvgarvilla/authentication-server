package com.webberis.ms.authenticationserver.secrets.service.impl;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.webberis.ms.authenticationserver.exception.KeySecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.WebberisGlobalException;
import com.webberis.ms.authenticationserver.secrets.KeyPairFile;
import com.webberis.ms.authenticationserver.secrets.service.SecretServiceAbstract;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.AutoAdaptableKubernetesClient;

public class KubernetesSecretService extends SecretServiceAbstract {
    
    private AutoAdaptableKubernetesClient adp;
    private Integer week;
    private Integer year;
    private String aliasName;
    
    public KubernetesSecretService(String aliasName) {
        this.adp = new AutoAdaptableKubernetesClient();
        Date now = new Date();
        this.week = Integer.valueOf(new SimpleDateFormat("w").format(now));
        this.year = Integer.valueOf(new SimpleDateFormat("y").format(now));
        this.aliasName = aliasName;
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
    public void done() {
        this.adp.close();
    }
    
    @Override
    public void cleanAndGenerateSecret(String ksSecretName, String publicSecretName, String alias) {
        Secret ksSecret = this.byName(ksSecretName).orElseThrow(() -> new SecretNotFoundException());
        cleanData(ksSecret.getData(), this.week - 1, this.year);
        
        Secret pubSecret = this.byName(ksSecretName).orElseThrow(() -> new SecretNotFoundException());
        cleanData(pubSecret.getData(), this.week - 1, this.year);
        
        KeyPairFile kpFile = new KeyPairFile(this.aliasName);
        
        this.updateSecretsByName(ksSecret, pubSecret, kpFile, week, year);
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
    
    /**
     * @param secret
     */
    private void validateActualWeek(Secret secret) {
        try {
            validateData(secret.getData(), this.week, this.year);
        } catch (KeySecretNotFoundException e) {
            throw new KeySecretNotFoundException("Actual week key not found. Generating it");
        } 
    }
    
    private void validateNextWeek(Secret secret) {
        try {
            validateData(secret.getData(), this.week + 1, this.year);
        } catch (KeySecretNotFoundException e) {
            throw new KeySecretNotFoundException("Next week key not found. Generating it");
        }
    }
    
    public static void validateData(Map<String, String> map, Integer week, Integer year) throws KeySecretNotFoundException {
        if (!map.containsKey(jksFormat(week, year)) || !map.containsKey(passFormat(week, year))) {
            throw new KeySecretNotFoundException();
        }
    }
    
    private void updateSecretsByName(Secret ksSecret, Secret pubSecret, KeyPairFile kpFile, Integer week, Integer year) {
        try {
            String keyStoreValue = encodeFile(kpFile.getJksFile());
            ksSecret.getData().put(jksFormat(week, year), keyStoreValue);
            
            String passValue = encodePassword(kpFile.getPassword());
            ksSecret.getData().put(passFormat(week, year), passValue);
            
            String pubKeyContent = encodeFile(kpFile.getPublicKey());
            pubSecret.getData().put(pubFormat(week, year), pubKeyContent);
            
            this.adp.secrets().createOrReplace(ksSecret);
            this.adp.secrets().createOrReplace(pubSecret);
        } catch (Exception e) {
            throw new WebberisGlobalException("Error while updating the keystore secret -> " + e.getMessage(), e);
        }
    }

}
