package com.webberis.ms.authenticationserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 
 * Class for wrapping security.jwt-signer properties
 * 
 * @author alvgarvilla
 *
 */
@Component
@ConfigurationProperties(prefix = "security.jwt-signer")
public class JwtSignerProperty {
	
    private boolean assymetric;
    private String signingKey;
	private String pubPath;
    private String ksPath; 
    private String ksAlias;
    private String k8sKsSecretName;
    private String k8sPubSecretName;
    
	public JwtSignerProperty() {}

	public boolean isAssymetric() {
		return assymetric;
	}

	public void setAssymetric(boolean assymetric) {
		this.assymetric = assymetric;
	}

	public String getSigningKey() {
		return signingKey;
	}

	public void setSigningKey(String signingKey) {
		this.signingKey = signingKey;
	}

	public String getPubPath() {
		return pubPath;
	}

	public void setPubPath(String pubPath) {
		this.pubPath = pubPath;
	}

	public String getKsPath() {
		return ksPath;
	}

	public void setKsPath(String ksPath) {
		this.ksPath = ksPath;
	}

	public String getKsAlias() {
		return ksAlias;
	}

	public void setKsAlias(String ksAlias) {
		this.ksAlias = ksAlias;
	}

	public String getK8sKsSecretName() {
		return k8sKsSecretName;
	}

	public void setK8sKsSecretName(String k8sKsSecretName) {
		this.k8sKsSecretName = k8sKsSecretName;
	}

	public String getK8sPubSecretName() {
		return k8sPubSecretName;
	}

	public void setK8sPubSecretName(String k8sPubSecretName) {
		this.k8sPubSecretName = k8sPubSecretName;
	}

}
