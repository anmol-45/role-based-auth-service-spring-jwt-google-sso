package com.authentication.app.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.Date;

@Component
public class JwtUtil {

    //using RSA Algorithm to sign the token

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

//    public JwtUtil() throws Exception {
//        this.privateKey = RsaKeyUtil.getPrivateKey("src/main/resources/private_key.pem");
//        this.publicKey = RsaKeyUtil.getPublicKey("src/main/resources/public_key.pem");
//    }
    public JwtUtil() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();

        this.privateKey = RsaKeyUtil.getPrivateKey(
                classLoader.getResourceAsStream("private_key.pem")
        );
        this.publicKey = RsaKeyUtil.getPublicKey(
                classLoader.getResourceAsStream("public_key.pem")
        );
    }


    public String generateToken(String email, String role) {
        return Jwts.builder()
                .subject(email)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hrs
                .signWith(privateKey)
                .compact();
    }


    public Claims validateToken(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUserEmail(String token) {
        return validateToken(token).getSubject();
    }

    public String extractUserRole(String token) {
        return validateToken(token).get("role", String.class);
    }
}
