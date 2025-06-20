package com.authentication.app.services.UserServiceImpl;

import com.authentication.app.entities.Admin;
import com.authentication.app.entities.User;
import com.authentication.app.repositories.AdminRepo;
import com.authentication.app.repositories.UserRepo;
import com.authentication.app.services.UserService;
import com.authentication.app.validation.UserValidation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service("adminService")
@RequiredArgsConstructor
@Slf4j
public class AdminServiceImpl implements UserService {

    private final UserRepo userRepo;
    private final AdminRepo adminRepo;

    @Override
    public User getDetails(String email) {
        log.debug("Getting admin details for email: {}", email);

        User user = userRepo.findByEmail(email);
        if (user == null) {
            log.warn("No admin found with email: {}", email);
            return null;
        }

        if (!"admin".equalsIgnoreCase(user.getRole())) {
            log.warn("Access denied: Not an admin: {}", email);
            return null;
        }

        return user;
    }

    public ResponseEntity<?> saveDetails(Admin adminUser) {
        log.debug("Received admin details from controller: {}", adminUser);

        String email = adminUser.getEmail();
        String role = adminUser.getRole();

        log.debug("Validating email: {}", email);
        if (!UserValidation.isEmailValid(email)) {
            log.warn("Invalid email format received: {}", email);
            return ResponseEntity.badRequest().body("Invalid email format. Please ensure it follows the format username@domain.com.");
        }

        log.debug("Validating role for the user: {}", role);
        if (!(role.equalsIgnoreCase("admin") || role.equalsIgnoreCase("teacher"))) {
            log.warn("Invalid role attempted to be saved: {}", role);
            return ResponseEntity.badRequest().body("Role must be either 'admin' or 'teacher'");
        }

        try {
            // Step 1: Check if user already exists in user table
            User existingUser = userRepo.findByEmail(email);
            if (existingUser != null) {
                log.debug("User found in user table: {}", email);

                // Step 2: Check if user already has the correct role
                if (existingUser.getRole().equalsIgnoreCase(role)) {
                    log.info("User already exists with the same role: {} - {}", email, role);
                    return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists with the role '" + role + "'");
                }

                // Step 3: If role is not correct, update in both places (user + admin)
                log.info("Updating role for existing user: {} from '{}' to '{}'", email, existingUser.getRole(), role);
                existingUser.setRole(role);
                userRepo.save(existingUser);

                Admin updatedAdmin = new Admin(email, role, LocalDateTime.now());
                adminRepo.save(updatedAdmin);

                log.info("Role updated successfully for user: {}", email);
                return ResponseEntity.ok("Role updated successfully for existing user");
            }

            // Step 4: If user doesn't exist in user table, just add to admin table
            log.info("User not found in user DB, creating admin entry for: {}", email);
            Admin newAdmin = new Admin(email, role, LocalDateTime.now());
            adminRepo.save(newAdmin);

            log.info("Admin details saved successfully for new admin: {}", email);
            return ResponseEntity.status(HttpStatus.CREATED).body("Admin details saved successfully");

        } catch (Exception e) {
            log.error("Error occurred while saving admin details for {}: {}", email, e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Internal Server Error while saving admin details");
        }
    }

}

