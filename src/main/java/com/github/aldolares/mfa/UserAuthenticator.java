package com.github.aldolares.mfa;

public interface UserAuthenticator {
    boolean authenticate(String user, String password) throws AuthenticationException;
}
