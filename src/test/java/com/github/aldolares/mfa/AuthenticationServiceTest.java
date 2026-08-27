package com.github.aldolares.mfa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationServiceTest {
    @Test
    void returnsTrueWhenAuthenticatorAcceptsCredentials() throws AuthenticationException {
        AuthenticationService service = new AuthenticationService((user, password) -> true);

        assertTrue(service.authenticate("alice", "secret"));
    }

    @Test
    void returnsFalseWhenAuthenticatorRejectsCredentials() throws AuthenticationException {
        AuthenticationService service = new AuthenticationService((user, password) -> false);

        assertFalse(service.authenticate("alice", "wrong"));
    }

    @Test
    void exposesAuthenticatorErrorsAsSoapFaults() {
        AuthenticationService service = new AuthenticationService((user, password) -> {
            throw new AuthenticationException("LDAP unavailable");
        });

        assertThrows(AuthenticationException.class, () -> service.authenticate("alice", "secret"));
    }
}
