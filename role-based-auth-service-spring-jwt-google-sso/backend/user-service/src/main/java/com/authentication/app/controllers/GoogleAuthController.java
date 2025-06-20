package com.authentication.app.controllers;


import com.authentication.app.services.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@RestController
@RequestMapping("/api/v1/googleAuth")
@RequiredArgsConstructor
@Slf4j
public class GoogleAuthController {
    private static final Logger logger = LoggerFactory.getLogger(GoogleAuthController.class);


    private final RestTemplate restTemplate;
    private final AuthService authService;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;


    @GetMapping("/callBack")
    public ResponseEntity<?> googleCallback(@RequestParam String code) {
        logger.info("Received Google OAuth callback with code: {}", code);

        try {
            String tokenEndpoint = "https://oauth2.googleapis.com/token";

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("code", code);
            params.add("client_id", clientId);  // from @Value
            params.add("client_secret", clientSecret);  // from @Value
            params.add("redirect_uri", "https://developers.google.com/oauthplayground");
            params.add("grant_type", "authorization_code");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            logger.info("Requesting token from Google for code...");

            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenEndpoint, request, Map.class);

            if (tokenResponse.getStatusCode() != HttpStatus.OK) {
                logger.error("Failed to retrieve token from Google: status {}", tokenResponse.getStatusCode());
                return new ResponseEntity<>("Failed to retrieve token", HttpStatus.UNAUTHORIZED);
            }

            String idToken = (String) tokenResponse.getBody().get("id_token");
            String userInfoUrl = "https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken;

            logger.info("Fetching user info from Google...");

            ResponseEntity<Map> userInfoResponse = restTemplate.getForEntity(userInfoUrl, Map.class);

            if (userInfoResponse.getStatusCode() == HttpStatus.OK) {
                Map userInfo = userInfoResponse.getBody();
                logger.info("User info received from Google: {}", userInfo);

                if (userInfo == null) {
                    logger.warn("User info response was null");
                    return new ResponseEntity<>("No user info received", HttpStatus.INTERNAL_SERVER_ERROR);
                }

                String email = (String) userInfo.get("email");
                String name = (String) userInfo.get("name");

                logger.info("Successfully retrieved user info: {} - {}", name, email);

                return authService.checkGoogleLogin(email, name);
            } else {
                logger.error("Failed to fetch user info from Google: status {}", userInfoResponse.getStatusCode());
                return new ResponseEntity<>("Unauthorized access", HttpStatus.UNAUTHORIZED);
            }

        } catch (Exception e) {
            logger.error("Exception during Google OAuth processing", e);
            return new ResponseEntity<>("Internal server error during Google login", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
