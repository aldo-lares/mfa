package com.github.aldolares.mfa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LdapConfigTest {
    @Test
    void acceptsSearchFilterWithExactlyOneUserPlaceholder() {
        LdapConfig config = new LdapConfig("ldap://localhost:389", "dc=example,dc=org", "(uid={0})",
                null, null, "com.sun.jndi.ldap.LdapCtxFactory");

        assertDoesNotThrow(config::validate);
    }

    @Test
    void rejectsSearchFilterWithoutExactlyOneUserPlaceholder() {
        assertThrows(AuthenticationException.class,
                () -> new LdapConfig("ldap://localhost:389", "dc=example,dc=org", "(uid=alice)",
                        null, null, "com.sun.jndi.ldap.LdapCtxFactory").validate());
        assertThrows(AuthenticationException.class,
                () -> new LdapConfig("ldap://localhost:389", "dc=example,dc=org", "(|(uid={0})(mail={0}))",
                        null, null, "com.sun.jndi.ldap.LdapCtxFactory").validate());
    }
}
