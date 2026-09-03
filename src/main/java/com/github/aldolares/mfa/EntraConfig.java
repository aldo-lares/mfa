package com.github.aldolares.mfa;

record EntraConfig(String tenantId, String clientId) {
    static EntraConfig fromEnvironment() {
        return new EntraConfig(
                Settings.setting("ENTRA_TENANT_ID", "entra.tenantId", null),
                Settings.setting("ENTRA_CLIENT_ID", "entra.clientId", null));
    }

    String tokenUrl() {
        return "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token";
    }

    void validate() throws AuthenticationException {
        if (tenantId == null || tenantId.isBlank()) {
            throw new AuthenticationException("ENTRA_TENANT_ID or entra.tenantId must be configured");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new AuthenticationException("ENTRA_CLIENT_ID or entra.clientId must be configured");
        }
    }
}