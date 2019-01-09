package com.webberis.ms.authenticationserver.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security", ignoreUnknownFields = false)
public class SecurityProperties {
	
	private List<String> clients;
	
	public List<String> getClients() {
		return clients;
	}
	
	public static class JwtSigner {
		
	}
	
	public static class OauthClients {
		
	}

}
