package com.bemojr.book_network.controller;

import com.bemojr.book_network.dto.AuthenticationRequest;
import com.bemojr.book_network.dto.AuthenticationResponse;
import com.bemojr.book_network.dto.RegistrationRequest;
import com.bemojr.book_network.service.AuthenticationService;
import freemarker.template.TemplateException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseEntity<?> register(
            @RequestBody @Valid RegistrationRequest request
    ) throws MessagingException, TemplateException, IOException {
        authenticationService.register(request);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody @Valid AuthenticationRequest request
    ) {
        AuthenticationResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/activate-account")
    public ResponseEntity<?> confirm(
            @RequestParam("token") String token
    ) throws MessagingException, TemplateException, IOException {
        authenticationService.activateAccount(token);
        return ResponseEntity.ok().build();
    }
}
