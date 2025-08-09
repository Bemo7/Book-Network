package com.bemojr.book_network.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;

@Builder
public record AuthenticationResponse(
        @NotEmpty(message = "Token should not be empty")
        @NotBlank(message = "Token should not be blank")
        String token
) {
}
