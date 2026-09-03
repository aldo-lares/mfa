package com.github.aldolares.mfa;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Pattern;

public class EntraUserAuthenticator implements UserAuthenticator {
    private static final Pattern ACCESS_TOKEN = Pattern.compile("\\\"access_token\\\"\\s*:\\s*\\\"([^\\\"]+)");
    private static final Pattern ERROR = Pattern.compile("\\\"error\\\"\\s*:\\s*\\\"([^\\\"]+)");
    private static final Pattern ERROR_DESCRIPTION = Pattern.compile("\\\"error_description\\\"\\s*:\\s*\\\"([^\\\"]+)");
    private static final System.Logger LOG = System.getLogger(EntraUserAuthenticator.class.getName());
    private final EntraConfig config;
    private final HttpClient client;

    public EntraUserAuthenticator(EntraConfig config) {
        this(config, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    EntraUserAuthenticator(EntraConfig config, HttpClient client) {
        this.config = config;
        this.client = client;
    }

    @Override
    public boolean authenticate(String user, String password) throws AuthenticationException {
        if (user == null || user.isBlank() || password == null || password.isBlank()) {
            LOG.log(System.Logger.Level.WARNING, "Entra authentication rejected blank credentials");
            return false;
        }
        config.validate();
        LOG.log(System.Logger.Level.INFO, "Starting Entra ROPC authentication for user {0}", safeUser(user));
        String body = form("grant_type", "password", "client_id", config.clientId(),
                "scope", "openid profile email", "username", user, "password", password);
        HttpRequest request = HttpRequest.newBuilder(URI.create(config.tokenUrl()))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            boolean authenticated = response.statusCode() == 200 && ACCESS_TOKEN.matcher(response.body()).find();
            if (authenticated) {
                LOG.log(System.Logger.Level.INFO, "Entra ROPC authentication succeeded for user {0}", safeUser(user));
            } else {
                LOG.log(System.Logger.Level.WARNING, "Entra ROPC authentication failed for user {0}; HTTP {1}; error={2}; description={3}",
                        safeUser(user), response.statusCode(), jsonValue(ERROR, response.body()),
                        jsonValue(ERROR_DESCRIPTION, response.body()));
            }
            return authenticated;
        } catch (IOException e) {
            LOG.log(System.Logger.Level.ERROR, "Unable to contact Entra during authentication for user " + safeUser(user), e);
            throw new AuthenticationException("Unable to contact Microsoft Entra ID", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.log(System.Logger.Level.ERROR, "Entra authentication interrupted for user " + safeUser(user), e);
            throw new AuthenticationException("Microsoft Entra authentication was interrupted", e);
        }
    }

    private static String jsonValue(Pattern pattern, String body) {
        var matcher = pattern.matcher(body);
        return matcher.find() ? matcher.group(1) : "none";
    }

    private static String safeUser(String user) {
        if (user.length() <= 3) {
            return "***";
        }
        int at = user.indexOf('@');
        if (at > 0) {
            return user.substring(0, Math.min(2, at)) + "***" + user.substring(at);
        }
        return user.substring(0, 2) + "***";
    }

    private static String form(String... values) {
        StringBuilder body = new StringBuilder();
        for (int index = 0; index < values.length; index += 2) {
            if (index > 0) {
                body.append('&');
            }
            body.append(URLEncoder.encode(values[index], StandardCharsets.UTF_8));
            body.append('=');
            body.append(URLEncoder.encode(values[index + 1], StandardCharsets.UTF_8));
        }
        return body.toString();
    }
}