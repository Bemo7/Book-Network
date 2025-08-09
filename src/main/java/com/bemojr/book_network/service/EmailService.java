package com.bemojr.book_network.service;

import com.bemojr.book_network.enumeration.EmailTemplateName;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Service;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@EnableAsync
public class EmailService {
    private final JavaMailSender javaMailSender;
    private final Configuration freemarkerConfig;

    @Async
    public void sendEmail(String to,
                          String username,
                          EmailTemplateName emailTemplate,
                          String confirmationUrl,
                          String subject,
                          String activationCode
    ) throws MessagingException, IOException, TemplateException {
        String templateName;

        if (emailTemplate == null) {
            templateName = "confirm_email";
        } else {
            templateName = emailTemplate.getName();
        }

        MimeMessage mimeMessage = javaMailSender.createMimeMessage();

        MimeMessageHelper helper = new MimeMessageHelper(
                mimeMessage,
                MimeMessageHelper.MULTIPART_MODE_MIXED,
                StandardCharsets.UTF_8.name()
        );

        Map<String, Object> properties = new HashMap<>();

        properties.put("username", username);
        properties.put("confirmationUrl", confirmationUrl);
        properties.put("activationCode", activationCode);

        Template template = freemarkerConfig.getTemplate(templateName);
        String html = FreeMarkerTemplateUtils.processTemplateIntoString(template, properties);

        helper.setTo(to);
        helper.setFrom("no-reply@gmail.com");
        helper.setSubject(subject);
        helper.setText(html, true);

        javaMailSender.send(mimeMessage);
    }
}
