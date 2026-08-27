package com.github.aldolares.mfa;

import jakarta.xml.ws.WebFault;

@WebFault(name = "AuthenticationFault", targetNamespace = "http://mfa.aldolares.github.com/")
public class AuthenticationException extends Exception {
    private static final long serialVersionUID = 1L;

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
