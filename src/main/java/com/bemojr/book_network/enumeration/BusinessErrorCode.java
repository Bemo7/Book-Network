package com.bemojr.book_network.enumeration;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum BusinessErrorCode {
    NO_CODE(0, HttpStatus.NOT_IMPLEMENTED, "No code"),
    ACCOUNT_LOCKED(300, HttpStatus.FORBIDDEN, "Account is locked"),
    INCORRECT_PASSWORD(301, HttpStatus.BAD_REQUEST, "Password is incorrect"),
    NEW_PASSWORD_DOES_NOT_MATCH(302, HttpStatus.BAD_REQUEST, "New password does not match"),
    ACCOUNT_DISABLED(303, HttpStatus.FORBIDDEN, "Account is disabled"),
    ACCOUNT_EXPIRED(304, HttpStatus.FORBIDDEN, "Account has expired"),
    BAD_CREDENTIALS(305, HttpStatus.FORBIDDEN, "Invalid Credentials");

    private final int code;
    private final HttpStatus httpStatusCode;
    private final String description;
}
