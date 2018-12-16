package com.webberis.ms.authenticationserver.config.converter.impl;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.io.IOUtils;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.webberis.ms.authenticationserver.config.converter.AbstractTokenConverter;
import com.webberis.ms.authenticationserver.secrets.KeyPairKubernetesSecret;

public class AsymmetricTokenConverter extends AbstractTokenConverter {
	
    private final String path;
    private final String alias;
    
    public AsymmetricTokenConverter(String path, String alias) {
        this.path = path;
        this.alias = alias;
    }

	@Override
	public void defineSigner() {
        try {
            Integer week = Integer.valueOf(new SimpleDateFormat("w").format(new Date())); 
            Integer year = Integer.valueOf(new SimpleDateFormat("y").format(new Date()));
            
            FileSystemResource jksResource = this.createKSResource(week, year);
            
            final KeyStoreKeyFactory ksKeyFactory = this.createKeyStoreKeyFactory(jksResource, week, year);
            
            super.setKeyPair(ksKeyFactory.getKeyPair(this.alias));
        } catch (Exception e) {
            LOGGER.error("Error setting the keypair " + e.getMessage(), e);
        }
	}
	
    public FileSystemResource createKSResource(Integer week, Integer year) 
            throws IOException {
        return new FileSystemResource(this.path + "/" + KeyPairKubernetesSecret.jksFormat(week, year));
    }
    
    public FileSystemResource createPassResource(Integer week, Integer year) 
            throws IOException {
        return new FileSystemResource(this.path + "/" + KeyPairKubernetesSecret.passFormat(week, year));
    }
    
    public KeyStoreKeyFactory createKeyStoreKeyFactory(FileSystemResource jksResource, Integer week, Integer year) 
            throws IOException {
        return new KeyStoreKeyFactory(jksResource, new String(getBytePass(week, year)).toCharArray());
    }
    
    private byte[] getBytePass(Integer week, Integer year) throws IOException {
        final FileSystemResource passResources = this.createPassResource(week, year);
        return IOUtils.toByteArray(passResources.getInputStream());
    }

}
