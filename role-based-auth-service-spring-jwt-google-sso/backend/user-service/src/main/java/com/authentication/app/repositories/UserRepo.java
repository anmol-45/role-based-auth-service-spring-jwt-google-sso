package com.authentication.app.repositories;

import com.authentication.app.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface

UserRepo extends JpaRepository<User, String> {
    User findByEmail(String email);
}
