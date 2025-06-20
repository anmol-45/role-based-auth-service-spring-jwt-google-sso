package com.authentication.app.repositories;

import com.authentication.app.entities.Admin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AdminRepo extends JpaRepository<Admin, String> {
    Admin getByEmail(String email);  // make sure this method exists in your Admin entity
}
