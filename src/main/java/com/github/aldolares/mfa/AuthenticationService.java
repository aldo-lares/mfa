package com.github.aldolares.mfa;

import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebService;

import java.util.Objects;

@WebService(serviceName = "AuthenticationService", targetNamespace = "http://mfa.aldolares.github.com/")
public class AuthenticationService {
    private final UserAuthenticator ldapAuthenticator;

    public AuthenticationService() throws AuthenticationException {
        this(defaultLdapAuthenticator());
    }

    AuthenticationService(UserAuthenticator authenticator) {
        this.ldapAuthenticator = Objects.requireNonNull(authenticator);
    }

    @WebMethod
    public AuthenticationResult authenticate(
            @WebParam(name = "user") String user,
            @WebParam(name = "password", mode = WebParam.Mode.IN) String password) throws AuthenticationException {
        return new AuthenticationResult(ldapAuthenticator.authenticate(user, password), user, "LDAP");
    }

    private static UserAuthenticator defaultLdapAuthenticator() throws AuthenticationException {
        LdapConfig config = LdapConfig.fromEnvironment();
        config.validate();
        return new LdapUserAuthenticator(config);
    }

}
