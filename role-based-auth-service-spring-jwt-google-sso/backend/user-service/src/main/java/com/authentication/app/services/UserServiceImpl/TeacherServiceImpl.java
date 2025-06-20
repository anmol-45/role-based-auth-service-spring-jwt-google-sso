package com.authentication.app.services.UserServiceImpl;

import com.authentication.app.entities.User;
import com.authentication.app.repositories.UserRepo;
import com.authentication.app.services.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service("teacherService")
@RequiredArgsConstructor
@Slf4j
public class TeacherServiceImpl implements UserService {

    private final UserRepo userRepo;

    @Override
    public User getDetails(String email) {
        log.debug("Getting teacher details for email: {}", email);

        User user = userRepo.findByEmail(email);
        if (user == null) {
            log.warn("No user found with email: {}", email);
            return null;
        }

        if (!"teacher".equalsIgnoreCase(user.getRole())) {
            log.warn("Access denied: Not a teacher: {}", email);
            return null;
        }

        return user;
    }
}
