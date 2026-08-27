package com.github.aldolares.mfa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationServiceTest {
    @Test
    void returnsTrueWhenAuthenticatorAcceptsCredentials() {
        AuthenticationService service = new AuthenticationService((user, password) -> true);

        assertTrue(service.authenticate("alice", "secret"));
    }

    @Test
    void returnsFalseWhenAuthenticatorRejectsCredentials() {
        AuthenticationService service = new AuthenticationService((user, password) -> false);

        assertFalse(service.authenticate("alice", "wrong"));
    }

    @Test
    void returnsFalseWhenAuthenticatorCannotCheckCredentials() {
        AuthenticationService service = new AuthenticationService((user, password) -> {
            throw new AuthenticationException("LDAP unavailable");
        });

        assertFalse(service.authenticate("alice", "secret"));
    }
}
