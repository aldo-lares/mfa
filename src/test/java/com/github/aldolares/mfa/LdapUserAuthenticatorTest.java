package com.github.aldolares.mfa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class LdapUserAuthenticatorTest {
    @Test
    void blankCredentialsAreRejectedWithoutDirectoryLookup() throws AuthenticationException {
        LdapUserAuthenticator authenticator = new LdapUserAuthenticator(new LdapConfig(null, null, null, null, null));

        assertFalse(authenticator.authenticate("", "secret"));
        assertFalse(authenticator.authenticate("alice", ""));
        assertFalse(authenticator.authenticate(null, "secret"));
        assertFalse(authenticator.authenticate("alice", null));
    }

    @Test
    void escapesLdapSearchFilterMetacharacters() {
        assertEquals("alice\\2a\\28admin\\29\\5c\\00", LdapUserAuthenticator.escapeFilterValue("alice*(admin)\\\u0000"));
    }
}
