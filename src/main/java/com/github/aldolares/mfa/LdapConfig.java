package com.github.aldolares.mfa;

record LdapConfig(
        String url,
        String baseDn,
        String userSearchFilter,
        String bindDn,
        String bindPassword) {
    private static final String DEFAULT_USER_SEARCH_FILTER = "(uid={0})";

    static LdapConfig fromEnvironment() {
        return new LdapConfig(
                setting("LDAP_URL", "ldap.url", null),
                setting("LDAP_BASE_DN", "ldap.baseDn", null),
                setting("LDAP_USER_SEARCH_FILTER", "ldap.userSearchFilter", DEFAULT_USER_SEARCH_FILTER),
                setting("LDAP_BIND_DN", "ldap.bindDn", null),
                setting("LDAP_BIND_PASSWORD", "ldap.bindPassword", null));
    }

    void validate() throws AuthenticationException {
        if (url == null || url.isBlank()) {
            throw new AuthenticationException("LDAP_URL or ldap.url must be configured");
        }
        if (baseDn == null || baseDn.isBlank()) {
            throw new AuthenticationException("LDAP_BASE_DN or ldap.baseDn must be configured");
        }
        if (userSearchFilter == null || userSearchFilter.isBlank() || !userSearchFilter.contains("{0}")) {
            throw new AuthenticationException("LDAP user search filter must contain {0}");
        }
    }

    private static String setting(String environmentName, String propertyName, String defaultValue) {
        String propertyValue = System.getProperty(propertyName);
        if (propertyValue != null && !propertyValue.isBlank()) {
            return propertyValue;
        }
        String environmentValue = System.getenv(environmentName);
        if (environmentValue != null && !environmentValue.isBlank()) {
            return environmentValue;
        }
        return defaultValue;
    }
}
