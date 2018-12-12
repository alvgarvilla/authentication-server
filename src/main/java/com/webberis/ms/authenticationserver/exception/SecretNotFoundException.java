package com.webberis.ms.authenticationserver.exception;

public class SecretNotFoundException extends WebberisGlobalException {
	
	private static final long serialVersionUID = 6735163712361248018L;

	public SecretNotFoundException() {
        super();
    }

    public SecretNotFoundException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public SecretNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecretNotFoundException(String message) {
        super(message);
    }

    public SecretNotFoundException(Throwable cause) {
        super(cause);
    }

}
