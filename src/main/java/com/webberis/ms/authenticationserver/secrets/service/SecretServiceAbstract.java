package com.webberis.ms.authenticationserver.secrets.service;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.webberis.ms.authenticationserver.exception.KeySecretNotFoundException;

public abstract class SecretServiceAbstract implements SecretService {
    
    private final static String JKS_FORMAT = "%d-%d.jks";
    private final static String PASS_FORMAT = "%d-%d.pass";
    private final static String PUB_FORMAT = "%d-%d.pub";
    
    protected static String encodePassword(char[] pass) {
        String passStr = new String(pass);
        return encodeBytes(passStr.getBytes());
    }
    
    protected static String encodeFile(File file) throws Exception {
        byte[] bytesFile = fileToBytesArray(file);
        return encodeBytes(bytesFile);
    }
    
    protected static String encodeBytes(byte[] bytes) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(bytes);
    }
    
    protected static byte[] fileToBytesArray(File file) throws Exception {
        int length = (int) file.length();
        BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file));
        byte[] bytes = new byte[length];
        reader.read(bytes, 0, length);
        reader.close();
        return bytes;
    }
    
    public static String jksFormat(Integer week, Integer year) {
        return String.format(JKS_FORMAT, week, year);
    }
    
    public static String passFormat(Integer week, Integer year) {
        return String.format(PASS_FORMAT, week, year);
    }
    
    protected static String pubFormat(Integer week, Integer year) {
        return String.format(PUB_FORMAT, week, year);
    }
    
    protected static void cleanData(Map<String, String> map, Integer week, Integer year) throws KeySecretNotFoundException {
        if (map == null) {
            map = new HashMap<>();
        } else {
            map.remove(jksFormat(week, year));
            map.remove(passFormat(week, year));    
        }
    }

}
