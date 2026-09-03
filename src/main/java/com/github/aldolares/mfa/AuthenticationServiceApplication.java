package com.github.aldolares.mfa;

import jakarta.xml.ws.Endpoint;

public final class AuthenticationServiceApplication {
    private AuthenticationServiceApplication() {
    }

    public static void main(String[] args) throws InterruptedException, AuthenticationException {
        String address = Settings.setting("SERVICE_ADDRESS", "service.address", "http://0.0.0.0:8080/auth");
        AuthenticationService service = new AuthenticationService();
        Endpoint.publish(address, service);
        System.out.printf("Authentication SOAP service listening at %s?wsdl%n", address);
        Thread.currentThread().join();
    }
}
