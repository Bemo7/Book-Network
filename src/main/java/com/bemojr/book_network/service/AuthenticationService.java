package com.bemojr.book_network.service;

import com.bemojr.book_network.enumeration.EmailTemplateName;
import com.bemojr.book_network.dto.AuthenticationRequest;
import com.bemojr.book_network.dto.AuthenticationResponse;
import com.bemojr.book_network.dto.RegistrationRequest;
import com.bemojr.book_network.entity.Role;
import com.bemojr.book_network.entity.Token;
import com.bemojr.book_network.entity.User;
import com.bemojr.book_network.repository.RoleRepository;
import com.bemojr.book_network.repository.TokenRepository;
import com.bemojr.book_network.repository.UserRepository;
import freemarker.template.TemplateException;
import jakarta.mail.MessagingException;
import jakarta.persistence.EntityExistsException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Value("${application.security.mailing.frontend.activation-url}")
    private String activationUrl;

    @Transactional
    public void register(RegistrationRequest request) throws MessagingException, TemplateException, IOException {
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

    private void sendValidationEmail(User user) throws MessagingException, TemplateException, IOException {
        String token = generateAndSaveActivationToken(user);

        emailService.sendEmail(
                user.getEmail(),
                user.fullName(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl,
                "Account Activation",
                token
        );
    }

    private String generateAndSaveActivationToken(User user) {
        String generatedToken = generateActivationCode(6);
        Token token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiredAt(LocalDateTime.now().plusMinutes(5))
                .users(user)
                .build();
        tokenRepository.save(token);

        return generatedToken;
    }

    private String generateActivationCode(int codeLength) {
        String characters = "0123456789";
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < codeLength; i++) {
            int randomIndex = new SecureRandom().nextInt(characters.length());
            stringBuilder.append(characters.charAt(randomIndex));
        }
        return stringBuilder.toString();
    }

    public AuthenticationResponse authenticate(@Valid AuthenticationRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        Map<String, Object> claims = new HashMap<>();
        User user = (User) authentication.getPrincipal();
        claims.put("fullName", user.fullName());

        String token = jwtService.generateToken(claims, user);

        return AuthenticationResponse.builder().token(token).build();
    }

    @Transactional
    public void activateAccount(String token) throws MessagingException, TemplateException, IOException {
        Token savedToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (LocalDateTime.now().isAfter(savedToken.getExpiredAt())) {
            sendValidationEmail(savedToken.getUsers());
            throw new RuntimeException("Activation token has expired. A new token has been sent to the same email address");
        }

        User user =  userRepository.findById(savedToken.getUsers().getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        user.setEnabled(true);
        userRepository.save(user);

        savedToken.setValidatedAt(LocalDateTime.now());

        tokenRepository.save(savedToken);
    }
}
