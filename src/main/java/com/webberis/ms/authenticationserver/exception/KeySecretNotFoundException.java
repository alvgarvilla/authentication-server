package com.webberis.ms.authenticationserver.exception;

public class KeySecretNotFoundException extends WebberisGlobalException {

	private static final long serialVersionUID = -5567230997283980107L; 
	
    public KeySecretNotFoundException() {
        super();
    }

    public KeySecretNotFoundException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public KeySecretNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeySecretNotFoundException(String message) {
        super(message);
    }

    public KeySecretNotFoundException(Throwable cause) {
        super(cause);
    }

}
