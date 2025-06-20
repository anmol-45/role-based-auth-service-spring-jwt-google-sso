package com.authentication.app.validation;

import com.authentication.app.dto.SignInRequestDto;
import com.authentication.app.dto.SignUpRequestDto;

import java.util.regex.Pattern;

public class UserValidation {

    // Best-practice email regex (RFC 5322 compliant but simplified)
    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}$";

    // Password must have:
    // - At least 1 uppercase
    // - At least 1 lowercase
    // - At least 1 digit
    // - At least 1 special character
    // - At least 8 characters in total
    private static final String PASSWORD_REGEX =
            "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$";

    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(PASSWORD_REGEX);

    // ✅ Check if fields are null or empty
    public static boolean isEmptyOrNull(SignUpRequestDto userRequest) {
        return userRequest == null
                || userRequest.email() == null || userRequest.email().trim().isEmpty()
                || userRequest.password() == null || userRequest.password().trim().isEmpty()
                || userRequest.firstName() == null || userRequest.firstName().trim().isEmpty()
                || userRequest.lastName() == null || userRequest.lastName().trim().isEmpty();
    }

    public static boolean isEmptyOrNull(SignInRequestDto userRequest) {
        return userRequest == null
                || userRequest.getEmail() == null || userRequest.getEmail().trim().isEmpty()
                || userRequest.getPassword() == null || userRequest.getPassword().trim().isEmpty();
    }

    // ✅ Validate email format
    public static boolean isEmailValid(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    // ✅ Validate password complexity
    public static boolean isPasswordValid(String password) {
        return password != null && PASSWORD_PATTERN.matcher(password).matches();
    }
}
