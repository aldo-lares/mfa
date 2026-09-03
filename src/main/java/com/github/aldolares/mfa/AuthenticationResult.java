package com.github.aldolares.mfa;

public class AuthenticationResult {
    private boolean authenticated;
    private String user;
    private String provider;

    public AuthenticationResult() {
    }

    public AuthenticationResult(boolean authenticated, String user, String provider) {
        this.authenticated = authenticated;
        this.user = user;
        this.provider = provider;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }
}