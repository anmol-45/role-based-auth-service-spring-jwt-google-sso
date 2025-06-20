# 🔐 Secure User Authentication and Authorization System

## **Overview**

This project implements a robust authentication and authorization system in a Spring Boot backend using:

✅ **JWT (JSON Web Tokens)** for stateless session management  
✅ **SSO with Google Sign-In** for seamless login  
✅ **Role-Based Access Control (RBAC)** with 3 roles:
- 👩‍🎓 **STUDENT**
- 👨‍🏫 **TEACHER**
- 👨‍💼 **ADMIN**

---

## **🔧 Tech Stack**

| Technology        | Purpose                            |
|------------------|------------------------------------|
| Spring Boot       | Backend framework                  |
| Spring Security   | Security and authorization         |
| JWT (`jjwt`/`auth0`) | Token generation and validation |
| Google Sign-In    | SSO identity provider              |
| MySQL             | User persistence                   |
| Lombok            | Cleaner code (getters/setters)     |

---

## **🔑 Authentication Flows**

### **🧾 1. JWT Username/Password Login (Manual Auth)**

**Flow:**

1. User hits `/api/v1/auth/register` with:
   ```json
   {
     "email": "student@gmail.com",
     "password": "secure123",
     "name": "Test Student"
   }
   ```

2. User logs in via `/api/v1/auth/login`, receives a JWT.

3. JWT is included in all subsequent requests as:
   ```http
   Authorization: Bearer <your-jwt-token>
   ```

---

### **🔐 2. SSO using Google Sign-In**

**Flow:**

1. Frontend (React/Vite) uses Google Sign-In SDK
2. It receives a **Google ID token**
3. Sends it to `/api/v1/auth/google`:
   ```json
   {
     "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
   }
   ```

4. Backend:
   - Validates the token using `GoogleIdTokenVerifier`
   - Creates user if not present
   - Assigns default role (e.g., `STUDENT`)
   - Issues a new **JWT**
   - Returns JWT to frontend

---

## **🎭 Roles & Authorization**

| Role     | Permissions                      |
|----------|----------------------------------|
| **STUDENT**  | View content, submit assignments |
| **TEACHER**  | Add content, grade submissions   |
| **ADMIN**    | Full access to all endpoints     |

---

## **🔐 Securing Endpoints**

Controller annotation:

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/dashboard")
public String adminPanel() {  }
```

Security config:

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/v1/auth/**").permitAll()
    .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
    .requestMatchers("/api/v1/teacher/**").hasAnyRole("TEACHER", "ADMIN")
    .requestMatchers("/api/v1/student/**").hasAnyRole("STUDENT", "TEACHER", "ADMIN")
    .anyRequest().authenticated()
);
```

---

## **🔄 Custom JWT Filter Chain**

A custom `JwtAuthFilter` is registered before `UsernamePasswordAuthenticationFilter` to:

- Extract the Bearer token from the Authorization header
- Parse and validate the JWT using RSA public key
- If valid, set `SecurityContextHolder` with user details

➡️ Enables downstream access via:

```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
String email = auth.getName();
```

This makes the user identity available across the request lifecycle.

---

## **🪙 JWT Claims Structure**

```json
{
  "sub": "user@gmail.com",
  "roles": ["ROLE_STUDENT"],
  "iat": 1718600000,
  "exp": 1718603600
}
```

---

## **🧱 Microservice Compatibility**

This module is designed with a microservice-first mindset:

- Stateless session management with JWT (no server-side session needed)
- Easily integrable with **Spring Cloud Gateway**, **Eureka Server**, and **Config Server**
- Google Sign-In as identity provider for unified SSO across services
- Role-based access ensures minimal endpoint exposure across services

---

## **📊 Role-Based Endpoint Access Table**

| Endpoint Pattern       | Method         | Roles Allowed           |
|------------------------|----------------|--------------------------|
| `/api/v1/student/**`   | GET            | STUDENT, TEACHER, ADMIN |
| `/api/v1/teacher/**`   | POST, PUT      | TEACHER, ADMIN          |
| `/api/v1/admin/**`     | GET, POST, DEL | ADMIN only              |

---

## **⚙️ Role Enforcement Strategies**

Role-based authorization is enforced using:

- **Annotations**:
  ```java
  @PreAuthorize("hasRole('ADMIN')")
  ```

- **HTTP Security Configuration**:
  ```java
  .authorizeHttpRequests(auth -> auth
      .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
  )
  ```

This double layer of protection ensures secure access control at both the method and request levels.

---

## **🧰 Project Structure**

```
src/
├── configFile/          # Security configs (SecurityConfig.java)
├── controllers/         # AuthController
├── dto/                 # UserRequestDto, UserResponseDto
├── services/            # AuthService
├── entities/            # User entity with roles
├── repository/          # UserRepository
└── utils/               # JwtService, GoogleTokenValidator
```

---

## **🛡️ Security Configuration Snippet**

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
   return http
           .csrf(AbstractHttpConfigurer::disable)
           .authorizeHttpRequests(auth -> auth
                   .requestMatchers("/api/v1/auth/**").permitAll()
                   .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                   .requestMatchers("/api/v1/teacher/**").hasAnyRole("TEACHER", "ADMIN")
                   .requestMatchers("/api/v1/student/**").hasAnyRole("STUDENT", "TEACHER", "ADMIN")
                   .anyRequest().authenticated()
           )
           .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
           .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
           .authenticationProvider(authenticationProvider)
           .build();
}
```

---

## **🚀 Environment Setup**

### **📦 Maven Dependencies**

```xml
<dependency>
   <groupId>io.jsonwebtoken</groupId>
   <artifactId>jjwt</artifactId>
   <version>0.11.5</version>
</dependency>

<dependency>
<groupId>com.google.api-client</groupId>
<artifactId>google-api-client</artifactId>
<version>2.2.0</version>
</dependency>
```

---

### **🔐 application.properties**

```properties
server.port=8082

# JWT
# RSA Key paths
jwt.private.key.path=classpath:private_key.pem
jwt.public.key.path=classpath:public_key.pem

app.jwt.expiration=3600000

# Logging
logging.level.org.springframework.security=DEBUG
```

---

## **✅ Sample API Testing with Postman**

| Endpoint                    | Method | Auth Required? | Description                  |
|----------------------------|--------|----------------|------------------------------|
| `/api/v1/auth/register`    | POST   | ❌ No           | Register new user            |
| `/api/v1/auth/login`       | POST   | ❌ No           | Login with email & password  |
| `/api/v1/auth/google`      | POST   | ❌ No           | Login via Google token       |
| `/api/v1/admin/dashboard`  | GET    | ✅ Yes (Admin)  | Protected admin data         |

---

## **🔒 Token Flow Visual**

```
[ Google SSO ] → ID Token → [ Backend ]
                      ↓
       Validate + Create JWT
                      ↓
         → Frontend stores JWT
                      ↓
         → Used for Authorization
```

---

## **✨ Future Improvements**

- ✅ Refresh token support
- ✅ Password reset
- ✅ Email verification
- ✅ Logout + token revocation
