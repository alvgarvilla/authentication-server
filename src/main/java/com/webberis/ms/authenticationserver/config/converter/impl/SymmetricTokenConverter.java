package com.webberis.ms.authenticationserver.config.converter.impl;

import com.webberis.ms.authenticationserver.config.converter.AbstractTokenConverter;

public class SymmetricTokenConverter extends AbstractTokenConverter {
	
    public SymmetricTokenConverter(String signingKey) {
        super.setSigningKey(signingKey);
    }

    @Override
    public void defineSigner() {
    }

}
