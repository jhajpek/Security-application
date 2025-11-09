package com.example.security.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class MailService {
    private final JavaMailSender mailSender;
    private final String from;
    private final String appUrl;

    public MailService(JavaMailSender mailSender,
                       @Value("${spring.mail.username}") String from,
                       @Value("${app.url}") String appUrl) {
        this.mailSender = mailSender;
        this.from = from;
        this.appUrl = appUrl;
    }

    public void sendVerificationMail(String to, UUID userId) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(from);
        msg.setTo(to);
        msg.setSubject("Verifikacija računa za SecurityApp");
        String link = appUrl + "/verify/" + userId.toString();
        msg.setText("Da biste verificirali račun, kliknite na: " + link);
        mailSender.send(msg);
    }

}
