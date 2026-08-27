package com.github.aldolares.mfa;

import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebService;

import java.util.Objects;

@WebService(serviceName = "AuthenticationService", targetNamespace = "http://mfa.aldolares.github.com/")
public class AuthenticationService {
    private final UserAuthenticator authenticator;

    public AuthenticationService() throws AuthenticationException {
        this(defaultAuthenticator());
    }

    AuthenticationService(UserAuthenticator authenticator) {
        this.authenticator = Objects.requireNonNull(authenticator);
    }

    @WebMethod
    public boolean authenticate(
            @WebParam(name = "user") String user,
            @WebParam(name = "password", mode = WebParam.Mode.IN) String password) throws AuthenticationException {
        return authenticator.authenticate(user, password);
    }

    private static UserAuthenticator defaultAuthenticator() throws AuthenticationException {
        LdapConfig config = LdapConfig.fromEnvironment();
        config.validate();
        return new LdapUserAuthenticator(config);
    }
}
