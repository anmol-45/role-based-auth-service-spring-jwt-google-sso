package com.authentication.app.services;

import com.authentication.app.entities.User;

public interface UserService {
    User getDetails(String email);
//    String updateDetails(String email, String name);
//    String deleteUser(String email);
}