package com.authentication.app.controllers;


import com.authentication.app.dto.SignInRequestDto;
import com.authentication.app.dto.SignUpRequestDto;
import com.authentication.app.dto.AuthResponse;
import com.authentication.app.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService){
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody SignUpRequestDto user){

        return authService.registerUser(user);

    }
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> logInUser(@RequestBody SignInRequestDto user){

        return authService.logInUser(user);

    }
}
