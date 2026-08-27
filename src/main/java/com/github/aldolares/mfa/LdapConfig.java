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
                Settings.setting("LDAP_URL", "ldap.url", null),
                Settings.setting("LDAP_BASE_DN", "ldap.baseDn", null),
                Settings.setting("LDAP_USER_SEARCH_FILTER", "ldap.userSearchFilter", DEFAULT_USER_SEARCH_FILTER),
                Settings.setting("LDAP_BIND_DN", "ldap.bindDn", null),
                Settings.setting("LDAP_BIND_PASSWORD", "ldap.bindPassword", null));
    }

    void validate() throws AuthenticationException {
        if (url == null || url.isBlank()) {
            throw new AuthenticationException("LDAP_URL or ldap.url must be configured");
        }
        if (baseDn == null || baseDn.isBlank()) {
            throw new AuthenticationException("LDAP_BASE_DN or ldap.baseDn must be configured");
        }
        if (userSearchFilter == null || userSearchFilter.isBlank() || placeholderCount(userSearchFilter) != 1) {
            throw new AuthenticationException("LDAP user search filter must contain exactly one {0}");
        }
    }

    private static int placeholderCount(String value) {
        int count = 0;
        int index = value.indexOf("{0}");
        while (index >= 0) {
            count++;
            index = value.indexOf("{0}", index + 3);
        }
        return count;
    }
}
