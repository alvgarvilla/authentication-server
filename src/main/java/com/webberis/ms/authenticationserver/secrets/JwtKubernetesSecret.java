package com.webberis.ms.authenticationserver.secrets;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.webberis.ms.authenticationserver.exception.KeySecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.SecretNotFoundException;
import com.webberis.ms.authenticationserver.exception.WebberisGlobalException;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.AutoAdaptableKubernetesClient;

public class JwtKubernetesSecret {
	
    private final static String JKS_FORMAT = "%d-%d.jks";
    private final static String PASS_FORMAT = "%d-%d.pass";
    private final static String PUB_FORMAT = "%d-%d.pub";
    
    private AutoAdaptableKubernetesClient adp;
    private String secret;
    
    public JwtKubernetesSecret(AutoAdaptableKubernetesClient adp, String secret) {
        this.adp = adp;
        this.secret = secret;
    }
    
    public Secret secretK8sJwt() throws SecretNotFoundException {
        Secret secret = this.byName(this.secret).orElseThrow(() -> new SecretNotFoundException());
        if (secret.getData() == null) {
            secret.setData(new HashMap<>());
        }
        return secret;
    }
    
    public static void validateData(Map<String, String> map, Integer week, Integer year) throws KeySecretNotFoundException {
        if (!map.containsKey(jksFormat(week, year)) || !map.containsKey(passFormat(week, year))) {
            throw new KeySecretNotFoundException();
        }
    }
    
    public static void cleanData(Map<String, String> map, Integer week, Integer year) throws KeySecretNotFoundException {
        map.remove(jksFormat(week, year));
        map.remove(passFormat(week, year));
    }
    
    public void updateSecret(Secret secret, KeyPairFile kpFile, String pubKeySecret, Integer week, Integer year) {
        
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
    
    public void done() {
        this.adp.close();
    }
    
    public static String jksFormat(Integer week, Integer year) {
        return String.format(JKS_FORMAT, week, year);
    }
    
    public static String passFormat(Integer week, Integer year) {
        return String.format(PASS_FORMAT, week, year);
    }
    
    public static String pubFormat(Integer week, Integer year) {
        return String.format(PUB_FORMAT, week, year);
    }
    
    private Optional<Secret> byName(String name) {
        return this.secrets().stream()
            .filter(s -> s.getMetadata().getName().equalsIgnoreCase(name))
            .findFirst();
    }
    
    private List<Secret> secrets() {
        return this.adp.secrets().list().getItems();
    }
    
    private static String encodePassword(char[] pass) {
        String passStr = new String(pass);
        return encodeBytes(passStr.getBytes());
    }
    
    private static String encodeFile(File file) throws Exception {
        byte[] bytesFile = fileToBytesArray(file);
        return encodeBytes(bytesFile);
    }
    
    private static String encodeBytes(byte[] bytes) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(bytes);
    }
    
    private static byte[] fileToBytesArray(File file) throws Exception {
        int length = (int) file.length();
        BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file));
        byte[] bytes = new byte[length];
        reader.read(bytes, 0, length);
        reader.close();
        return bytes;
    }
    
    private static void secretPublicKey(Secret pubSecret, KeyPairFile kpFile, Integer week, Integer year) throws Exception {
        if (pubSecret.getData() == null) {
            pubSecret.setData(new HashMap<>());
        }
        String pubKeyContent = encodeFile(kpFile.getPublicKey());
        pubSecret.getData().put(pubFormat(week, year), pubKeyContent);
    }

}
