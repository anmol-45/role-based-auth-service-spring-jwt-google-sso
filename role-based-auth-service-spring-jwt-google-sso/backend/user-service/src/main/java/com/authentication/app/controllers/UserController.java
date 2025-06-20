package com.authentication.app.controllers;

import com.authentication.app.entities.User;
import com.authentication.app.services.UserServiceImpl.AdminServiceImpl;
import com.authentication.app.services.UserServiceImpl.StudentServiceImpl;
import com.authentication.app.services.UserServiceImpl.TeacherServiceImpl;

import com.authentication.app.validation.UserValidation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final StudentServiceImpl studentService;
    private final TeacherServiceImpl teacherService;
    private final AdminServiceImpl adminService;

    @GetMapping("/student/{email}")
    @PreAuthorize("hasRole('STUDENT')")
    public ResponseEntity<?> getStudentDetails(@PathVariable String email) {
        log.info("Fetching student details for email: {}", email);

        if (!UserValidation.isEmailValid(email)) {
            log.warn("Invalid email format: {}", email);
            return ResponseEntity.badRequest().body("Invalid email format");
        }

        try {
            User user = studentService.getDetails(email);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            log.error("Error fetching student details: {}", e.getMessage());
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    @GetMapping("/teacher/{email}")
    @PreAuthorize("hasRole('TEACHER')")
    public ResponseEntity<?> getTeacherDetails(@PathVariable String email) {
        log.info("Fetching teacher details for email: {}", email);

        if (!UserValidation.isEmailValid(email)) {
            log.warn("Invalid email format: {}", email);
            return ResponseEntity.badRequest().body("Invalid email format");
        }

        try {
            User user = teacherService.getDetails(email);
            if (user == null) {
                return ResponseEntity.badRequest().body("Invalid role or user not found");
            }
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            log.error("Error fetching teacher details: {}", e.getMessage());
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    @GetMapping("/admin/{email}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAdminDetails(@PathVariable String email) {
        log.info("Fetching admin details for email: {}", email);

        if (!UserValidation.isEmailValid(email)) {
            log.warn("Invalid email format: {}", email);
            return ResponseEntity.badRequest().body("Invalid email format");
        }

        try {
            User user = adminService.getDetails(email);
            if (user == null) {
                return ResponseEntity.badRequest().body("Admin not found");
            }
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            log.error("Error fetching admin details: {}", e.getMessage());
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }
}
