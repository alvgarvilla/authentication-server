package com.webberis.ms.authenticationserver.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
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

import com.webberis.ms.authenticationserver.config.converter.impl.AsymmetricTokenConverter;
import com.webberis.ms.authenticationserver.config.converter.impl.SymmetricTokenConverter;
import com.webberis.ms.authenticationserver.service.UserService;

@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private Environment env;

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager).tokenStore(tokenStore())
				.tokenEnhancer(accessTokenConverter()).userDetailsService(userService);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource).passwordEncoder(new BCryptPasswordEncoder());
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
		boolean isAssymEncrypt = Boolean.valueOf(env.getProperty("mvg.security.jwt-signer.assymetric"));
		if (isAssymEncrypt) {
			tokenConverter = new AsymmetricTokenConverter(env.getProperty("mvg.security.jwt-signer.ks-path"),
					env.getProperty("mvg.security.jwt-signer.ks-alias"));
		} else {
			tokenConverter = new SymmetricTokenConverter(env.getProperty("mvg.security.jwt-signer.signing-key"));
		}
		return tokenConverter;
	}

}
