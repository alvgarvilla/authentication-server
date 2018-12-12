package com.webberis.ms.authenticationserver.exception;

public class WebberisGlobalException extends RuntimeException {

	private static final long serialVersionUID = -5020895757074418088L;
	
    public WebberisGlobalException() {
        super();
    }

    public WebberisGlobalException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public WebberisGlobalException(String message, Throwable cause) {
        super(message, cause);
    }

    public WebberisGlobalException(String message) {
        super(message);
    }

    public WebberisGlobalException(Throwable cause) {
        super(cause);
    }

}
