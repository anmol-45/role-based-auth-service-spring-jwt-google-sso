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
import java.util.Arrays;
import java.util.UUID;


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


    public ResponseEntity<?> checkGoogleLogin(String email, String name) {
        logger.info("Processing Google login for email: {}", email);

        User user = userRepo.findByEmail(email);

        if (user == null) {
            logger.info("No user found with email: {}, creating a new one", email);

            Admin userFromAdminDb = null;
            try {
                userFromAdminDb = adminRepo.getByEmail(email);
            } catch (Exception e) {
                logger.error("Failed to fetch admin from DB for email: {}", email, e);
            }

            String[] nameArray = name.split(" ");
            String firstName = nameArray.length > 0 ? nameArray[0] : "";
            String lastName = nameArray.length > 1 ? nameArray[1] : "";

            User userForDb = new User();
            userForDb.setRole(userFromAdminDb == null ? "student" : userFromAdminDb.getRole());
            userForDb.setEmail(email);
            userForDb.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            userForDb.setFirstName(firstName);
            userForDb.setLastName(lastName);
            userForDb.setCreatedAt(LocalDateTime.now());

            try {
                userRepo.save(userForDb);
                logger.info("User registered successfully: {}", email);
                return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
            } catch (Exception e) {
                logger.error("Error while saving user to DB: {}", email, e);
                return new ResponseEntity<>("Internal Server Error while saving user", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } else {
            logger.info("User exists, generating token for: {}", email);
            String accessToken = jwtUtil.generateToken(email, user.getRole());

            AuthResponse authResponse = new AuthResponse();
            authResponse.setRole(user.getRole());
            authResponse.setToken(accessToken);
            authResponse.setName(user.getFirstName() + " " + user.getLastName());

            return new ResponseEntity<>(authResponse, HttpStatus.ACCEPTED);
        }
    }

}
