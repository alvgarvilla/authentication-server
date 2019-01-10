package com.webberis.ms.authenticationserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.webberis.ms.authenticationserver.config.converter.impl.AssymetricTokenConverter;
import com.webberis.ms.authenticationserver.config.converter.impl.SymmetricTokenConverter;
import com.webberis.ms.authenticationserver.service.UserService;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserService userService;
	
	@Autowired
	private JwtSignerProperty jwtSignerProperties;
	
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager)
		        .tokenStore(tokenStore())
				.tokenEnhancer(accessTokenConverter())
				.userDetailsService(userService);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		clients.inMemory()
			.withClient("web")
			.secret("{bcrypt}".concat(passwordEncoder.encode("web123")))
			.autoApprove(true)
			.authorizedGrantTypes("implicit","refresh_token", "password", "authorization_code")
			.scopes("web")
		.and()
			.withClient("test")
			.secret("{bcrypt}".concat(passwordEncoder.encode("test123")))
			.autoApprove(true)
			.authorizedGrantTypes("client_credentials")
			.scopes("test_scope");
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

	@Bean
	@Primary
	public DefaultTokenServices tokenServices() {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore());
		defaultTokenServices.setSupportRefreshToken(true);
		return defaultTokenServices;
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter tokenConverter;
		if (jwtSignerProperties.isAssymetric()) {
			tokenConverter = new AssymetricTokenConverter(jwtSignerProperties.getKsPath(),
					jwtSignerProperties.getKsAlias());
		} else {
			tokenConverter = new SymmetricTokenConverter(jwtSignerProperties.getSigningKey());
		}
		return tokenConverter;
	}

}
