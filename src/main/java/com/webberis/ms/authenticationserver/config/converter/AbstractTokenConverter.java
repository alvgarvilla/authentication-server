package com.webberis.ms.authenticationserver.config.converter;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

public abstract class AbstractTokenConverter extends JwtAccessTokenConverter {
	
	protected static final Logger LOGGER = LoggerFactory.getLogger(AbstractTokenConverter.class);
	
    public abstract void defineSigner();
    
    /**
     * In case of password grant_type, some additional info will be added into the token.
     * Once the information is added and encoded into the access and refresh tokens, the AdditionalInfo attribute
     * from the accessTokenResponse will be deleted in order to avoid duplicates.
     * 
     * @param OAuth2AccessToken accessToken, OAuth2Authentication authentication
     * @return OAuth2AccessToken the modified access token
     */
    @Override
    public OAuth2AccessToken enhance(final OAuth2AccessToken accessToken,
            final OAuth2Authentication authentication) {
        if(includeUserData(authentication)) {
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(attachAdditionalInfo(authentication));    
        }
        this.defineSigner();
        
        final OAuth2AccessToken newAccessToken = this.callEnhanceParent(accessToken, authentication);
        ((DefaultOAuth2AccessToken) newAccessToken).setAdditionalInformation(new HashMap<>());
        return newAccessToken;
    }
    
    public OAuth2AccessToken callEnhanceParent(final OAuth2AccessToken accessToken,
            final OAuth2Authentication authentication) {
        return super.enhance(accessToken, authentication);
    }
    
    private Map<String, Object> attachAdditionalInfo(final OAuth2Authentication authentication) {
        final Map<String, Object> additionalInfo = new HashMap<String, Object>();
        return additionalInfo;
    }
    
    private static boolean includeUserData(final OAuth2Authentication authentication) {
        return authentication.getOAuth2Request().getGrantType() == null && authentication.getPrincipal() != null
                || authentication.getOAuth2Request().getGrantType() != null && authentication.getOAuth2Request().getGrantType().equalsIgnoreCase("password"); 
    }

}
