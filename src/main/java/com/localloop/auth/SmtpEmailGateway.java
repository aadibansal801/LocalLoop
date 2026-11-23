package com.localloop.auth;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
class SmtpEmailGateway implements EmailGateway {
    private final JavaMailSender sender;
    private final AuthSettings settings;

    SmtpEmailGateway(JavaMailSender sender, AuthSettings settings) {
        this.sender = sender;
        this.settings = settings;
    }

    @Override
    public void send(String recipient, String subject, String body) {
        var message = new SimpleMailMessage();
        message.setFrom(settings.mailFrom);
        message.setTo(recipient);
        message.setSubject(subject);
        message.setText(body);
        sender.send(message);
    }
}
