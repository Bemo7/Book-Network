package com.bemojr.book_network.service;

import com.bemojr.book_network.dto.RegistrationRequest;
import com.bemojr.book_network.entity.Role;
import com.bemojr.book_network.entity.Token;
import com.bemojr.book_network.entity.User;
import com.bemojr.book_network.repository.RoleRepository;
import com.bemojr.book_network.repository.TokenRepository;
import com.bemojr.book_network.repository.UserRepository;
import jakarta.mail.internet.MimeMessage;
import jakarta.persistence.EntityExistsException;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender javaMailSender;

    public void register(RegistrationRequest request) {
        Role role = roleRepository.findByName("USER").orElseThrow(()-> new EntityNotFoundException("Role 'USER' has not been initialized"));

        Optional<User> existingUser = userRepository.findByEmail(request.email());

        if (existingUser.isPresent()) throw new EntityExistsException("User already exists");

        User user = User.builder()
                .email(request.email())
                .firstName(request.firstName())
                .lastName(request.lastName())
                .password(
                        passwordEncoder.encode(
                                request.password()
                        )
                )
                .enabled(false)
                .accountLocked(false)
                .roles(List.of(role))
                .build();

        userRepository.save(user);
        sendValidationEmail(user);
    }

    private void sendValidationEmail(User user) {
        String token = generateAndSaveActivationToken(user);

        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        javaMailSender.send(mimeMessage);
    }

    private String generateAndSaveActivationToken(User user) {
        String generatedToken = generateActivationCode(6);
        Token token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiredAt(LocalDateTime.now().plusMinutes(5))
                .build();
        tokenRepository.save(token);

        return generatedToken;
    }

    private String generateActivationCode(int codeLength) {
        String characters = "0123456789";
        StringBuilder codeBuilder = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();

        for (int i = 0; i < codeLength; i++) {
            int randomIndex = secureRandom.nextInt();
            codeBuilder.append(characters.charAt(randomIndex));
        }

        return codeBuilder.toString();
    }
}
