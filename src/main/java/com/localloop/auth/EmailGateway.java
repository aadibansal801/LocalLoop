package com.localloop.auth;

public interface EmailGateway {
    void send(String recipient, String subject, String body);
}
