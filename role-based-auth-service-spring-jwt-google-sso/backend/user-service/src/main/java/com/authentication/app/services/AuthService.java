package com.authentication.app.services;

import com.authentication.app.dto.SignInRequestDto;
import com.authentication.app.dto.SignUpRequestDto;
import com.authentication.app.dto.AuthResponse;
import com.authentication.app.entities.Admin;
import com.authentication.app.entities.User;
import com.authentication.app.repositories.AdminRepo;
import com.authentication.app.repositories.UserRepo;
import com.authentication.app.util.JwtUtil;
import com.authentication.app.validation.UserValidation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;


@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepo userRepo;
    private final AdminRepo adminRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Autowired
    public AuthService(UserRepo userRepo, AdminRepo adminRepo , PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepo = userRepo;
        this.adminRepo = adminRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public ResponseEntity<String> registerUser(SignUpRequestDto userRequest) {
        logger.info("Attempting to register user with email: {}", userRequest.email());


        //this basic checks should be done using class called validation to validate emptiness or regex of email and password
        if(UserValidation.isEmptyOrNull(userRequest)){
            logger.warn("Validation failed: email, name or password is empty.");
            return new ResponseEntity<>("Invalid input data", HttpStatus.BAD_REQUEST);

        }

        // Validate email format
        if (!UserValidation.isEmailValid(userRequest.email())) {
            logger.warn("Invalid email format: {}", userRequest.email());
            return new ResponseEntity<>("Invalid email format", HttpStatus.BAD_REQUEST);
        }

        // Validate password format
        if (!UserValidation.isPasswordValid(userRequest.password())) {
            logger.warn("Weak password provided");
            return new ResponseEntity<>("Password must contain at least 8 characters, one uppercase letter, one digit, and one special character.", HttpStatus.BAD_REQUEST);
        }

        if (userRepo.findById(userRequest.email()).isPresent()) {
            logger.warn("User already exists with email: {}", userRequest.email());
            return new ResponseEntity<>("User already exists", HttpStatus.CONFLICT);
        }

        Admin userFromAdminDb = null;
        try {
            userFromAdminDb = adminRepo.getByEmail(userRequest.email());
        } catch (Exception e) {
            logger.error("Error fetching admin from DB", e);
        }

        User user = new User();
        user.setRole(userFromAdminDb == null ? "student" : userFromAdminDb.getRole());
        user.setEmail(userRequest.email());
        user.setPassword(passwordEncoder.encode(userRequest.password()));
        user.setFirstName(userRequest.firstName());
        user.setLastName(userRequest.lastName());
        user.setCreatedAt(LocalDateTime.now());

        try {
            userRepo.save(user);
            logger.info("User successfully registered with email: {}", user.getEmail());
            return new ResponseEntity<>("User added successfully", HttpStatus.CREATED);
        } catch (Exception e) {
            logger.error("Error saving user", e);
            return new ResponseEntity<>("Unable to save data in db", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<AuthResponse> logInUser(SignInRequestDto signInRequest) {


        if(UserValidation.isEmptyOrNull(signInRequest)){
            logger.warn("Validation failed: email or password is empty.");
            throw new RuntimeException("Validation failed: email or password is empty.");

        }

        String email = signInRequest.getEmail();
        String password = signInRequest.getPassword();

        if(!UserValidation.isEmailValid(email))
            throw new RuntimeException("Invalid email format. Please ensure it follows the format username@domain.com.");

        if(!UserValidation.isPasswordValid(password))
            throw new RuntimeException("Password must be 8-16 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.");


        User user = userRepo.findByEmail(email);

        if (user == null) {
            throw new RuntimeException("No user found with the provided email address.");
        }

        if(!passwordEncoder.matches(password , user.getPassword())){

            throw new RuntimeException("Authentication failed: Incorrect Password");

        }

        String accessToken = jwtUtil.generateToken(email, user.getRole());
        // Create AuthResponse object to return
        AuthResponse authResponse = new AuthResponse();
        authResponse.setRole(user.getRole());
        authResponse.setToken(accessToken);
        authResponse.setName(user.getFirstName() + " " + user.getLastName());
        return new ResponseEntity<>(authResponse , HttpStatus.ACCEPTED);





    }
}
