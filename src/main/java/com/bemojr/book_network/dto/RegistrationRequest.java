package com.bemojr.book_network.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record RegistrationRequest(
        @NotEmpty(message = "First name should not be empty")
        @NotBlank(message = "First name should not be blank")
        String firstName,

        @NotEmpty(message = "Last name should not be empty")
        @NotBlank(message = "Last name should not be blank")
        String lastName,

        @Email(message = "Email should be in a valid format")
        @NotEmpty(message = "Email should not be empty")
        @NotBlank(message = "Email should not be blank")
        String email,

        @NotEmpty(message = "Password should not be empty")
        @NotBlank(message = "Password should not be blank")
        @Size(min = 8, message = "Password should not be less than 8 characters")
        String password
) {
}
