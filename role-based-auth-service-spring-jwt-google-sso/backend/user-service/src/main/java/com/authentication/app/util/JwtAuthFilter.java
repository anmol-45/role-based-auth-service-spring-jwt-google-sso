package com.authentication.app.util;

import com.authentication.app.entities.User;
import com.authentication.app.repositories.UserRepo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepo userRepo;

    @Autowired
    public JwtAuthFilter(JwtUtil jwtUtil, UserRepo userRepo) {
        this.jwtUtil = jwtUtil;
        this.userRepo = userRepo;
    }

    @Override //This method is to be called in all the requests unless its excluded in config
    protected void doFilterInternal(
            HttpServletRequest request,
             @NonNull HttpServletResponse response,
             @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        //Extract the authorization header from the request
        final String authHeader = request.getHeader("Authorization");
        final String token;

        //If the header is empty or doesn't start with "Bearer" then skip the JWT validation
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        //Extract the actual token from the header
        token = authHeader.substring(7);

        try{

            //validate the token and extract the claims
            Claims claims = jwtUtil.validateToken(token);
            String email = claims.getSubject();
            String role = claims.get("role", String.class);

            //If Email and role are present in the token, then:
            if(email != null && role != null){
                //look up the user in the DynamoDB
                User user =userRepo.findByEmail(email);

                //User exists and Roles match.
                if (user != null && user.getRole().equalsIgnoreCase(role)){

                    //Downstream access to logged-in User's identity
//                    setting the security details for securityContextHolder
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            email,
                            null,
                            List.of(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                    );
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    //Allow the Request to proceed
                    filterChain.doFilter(request,response);
                    return;
                }
            }

            //if email and role mismatch, then Forbidden
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("Forbidden: Invalid token or role mismatch");

        }
        catch (JwtException e){
            // If token is invalid, expired, malformed, etc., return 401 Unauthorized
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Unauthorized: Invalid or expired token");
        }
    }

}
