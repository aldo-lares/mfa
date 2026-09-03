package com.github.aldolares.mfa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationServiceTest {
    @Test
    void returnsTrueWhenAuthenticatorAcceptsCredentials() throws AuthenticationException {
        AuthenticationService service = new AuthenticationService((user, password) -> true);

        assertTrue(service.authenticate("alice", "secret").isAuthenticated());
    }

    @Test
    void returnsFalseWhenAuthenticatorRejectsCredentials() throws AuthenticationException {
        AuthenticationService service = new AuthenticationService((user, password) -> false);

        assertFalse(service.authenticate("alice", "wrong").isAuthenticated());
    }

    @Test
    void exposesAuthenticatorErrorsAsSoapFaults() {
        AuthenticationService service = new AuthenticationService((user, password) -> {
            throw new AuthenticationException("LDAP unavailable");
        });

        assertThrows(AuthenticationException.class, () -> service.authenticate("alice", "secret"));
    }

    @Test
    void identifiesLdapAsAuthenticationProvider() throws AuthenticationException {
        AuthenticationService service = new AuthenticationService((user, password) -> true);

        AuthenticationResult result = service.authenticate("alice", "password");

        assertTrue(result.isAuthenticated());
        assertEquals("LDAP", result.getProvider());
    }

}
