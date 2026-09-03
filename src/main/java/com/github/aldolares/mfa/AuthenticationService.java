package com.github.aldolares.mfa;

import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebService;

import java.util.Objects;

@WebService(serviceName = "AuthenticationService", targetNamespace = "http://mfa.aldolares.github.com/")
public class AuthenticationService {
    private static final String DEFAULT_ENTRA_DOMAIN = "MngEnv229286.onmicrosoft.com";
    private final UserAuthenticator ldapAuthenticator;
    private final UserAuthenticator entraAuthenticator;

    public AuthenticationService() throws AuthenticationException {
        this(defaultLdapAuthenticator(), defaultEntraAuthenticator());
    }

    AuthenticationService(UserAuthenticator authenticator) {
        this(authenticator, null);
    }

    AuthenticationService(UserAuthenticator ldapAuthenticator, UserAuthenticator entraAuthenticator) {
        this.ldapAuthenticator = Objects.requireNonNull(ldapAuthenticator);
        this.entraAuthenticator = entraAuthenticator;
    }

    @WebMethod
    public AuthenticationResult authenticate(
            @WebParam(name = "user") String user,
            @WebParam(name = "password", mode = WebParam.Mode.IN) String password) throws AuthenticationException {
        boolean entraUser = isEntraUser(user);
        UserAuthenticator selectedAuthenticator = entraUser ? entraAuthenticator : ldapAuthenticator;
        String provider = entraUser ? "ENTRA" : "LDAP";
        if (selectedAuthenticator == null) {
            throw new AuthenticationException("Entra authentication is not configured");
        }
        return new AuthenticationResult(selectedAuthenticator.authenticate(user, password), user, provider);
    }

    static boolean isEntraUser(String user) {
        String domain = Settings.setting("ENTRA_PRIMARY_DOMAIN", "entra.primaryDomain", DEFAULT_ENTRA_DOMAIN);
        return user != null && user.toLowerCase().endsWith("@" + domain.toLowerCase());
    }

    private static UserAuthenticator defaultLdapAuthenticator() throws AuthenticationException {
        LdapConfig config = LdapConfig.fromEnvironment();
        config.validate();
        return new LdapUserAuthenticator(config);
    }

    private static UserAuthenticator defaultEntraAuthenticator() throws AuthenticationException {
        EntraConfig config = EntraConfig.fromEnvironment();
        config.validate();
        return new EntraUserAuthenticator(config);
    }
}
