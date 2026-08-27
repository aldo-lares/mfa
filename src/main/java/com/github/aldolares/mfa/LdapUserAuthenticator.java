package com.github.aldolares.mfa;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

public class LdapUserAuthenticator implements UserAuthenticator {
    private final LdapConfig config;

    public LdapUserAuthenticator(LdapConfig config) {
        this.config = config;
    }

    @Override
    public boolean authenticate(String user, String password) throws AuthenticationException {
        if (user == null || user.isBlank() || password == null || password.isBlank()) {
            return false;
        }

        config.validate();
        String userDn = findUserDn(user);
        if (userDn == null) {
            return false;
        }
        return bindAsUser(userDn, password);
    }

    private String findUserDn(String user) throws AuthenticationException {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[0]);

        String filter = config.userSearchFilter().replace("{0}", escapeFilterValue(user));
        DirContext context = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            context = new InitialDirContext(searchEnvironment());
            results = context.search(config.baseDn(), filter, controls);
            if (!results.hasMore()) {
                return null;
            }
            return results.next().getNameInNamespace();
        } catch (NamingException e) {
            throw new AuthenticationException("Unable to search LDAP directory", e);
        } finally {
            close(results);
            close(context);
        }
    }

    private boolean bindAsUser(String userDn, String password) throws AuthenticationException {
        Hashtable<String, String> environment = baseEnvironment();
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, userDn);
        environment.put(Context.SECURITY_CREDENTIALS, password);

        DirContext context = null;
        try {
            context = new InitialDirContext(environment);
            return true;
        } catch (javax.naming.AuthenticationException e) {
            return false;
        } catch (NamingException e) {
            throw new AuthenticationException("Unable to bind to LDAP directory", e);
        } finally {
            close(context);
        }
    }

    private Hashtable<String, String> searchEnvironment() {
        Hashtable<String, String> environment = baseEnvironment();
        if (config.bindDn() != null && !config.bindDn().isBlank()) {
            environment.put(Context.SECURITY_AUTHENTICATION, "simple");
            environment.put(Context.SECURITY_PRINCIPAL, config.bindDn());
            environment.put(Context.SECURITY_CREDENTIALS, config.bindPassword() == null ? "" : config.bindPassword());
        }
        return environment;
    }

    private Hashtable<String, String> baseEnvironment() {
        Hashtable<String, String> environment = new Hashtable<>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, config.url());
        return environment;
    }

    static String escapeFilterValue(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '\\' -> escaped.append("\\5c");
                case '*' -> escaped.append("\\2a");
                case '(' -> escaped.append("\\28");
                case ')' -> escaped.append("\\29");
                case '\u0000' -> escaped.append("\\00");
                default -> escaped.append(character);
            }
        }
        return escaped.toString();
    }

    private static void close(DirContext context) throws AuthenticationException {
        if (context != null) {
            try {
                context.close();
            } catch (NamingException e) {
                throw new AuthenticationException("Unable to close LDAP context", e);
            }
        }
    }

    private static void close(NamingEnumeration<SearchResult> results) throws AuthenticationException {
        if (results != null) {
            try {
                results.close();
            } catch (NamingException e) {
                throw new AuthenticationException("Unable to close LDAP search results", e);
            }
        }
    }
}
