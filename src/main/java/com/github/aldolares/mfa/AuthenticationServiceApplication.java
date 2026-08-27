package com.github.aldolares.mfa;

import jakarta.xml.ws.Endpoint;

import java.util.concurrent.CountDownLatch;

public final class AuthenticationServiceApplication {
    private AuthenticationServiceApplication() {
    }

    public static void main(String[] args) throws InterruptedException {
        String address = setting("SERVICE_ADDRESS", "service.address", "http://0.0.0.0:8080/auth");
        Endpoint.publish(address, new AuthenticationService());
        System.out.printf("Authentication SOAP service listening at %s?wsdl%n", address);
        new CountDownLatch(1).await();
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
