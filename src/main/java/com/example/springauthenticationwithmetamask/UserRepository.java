package com.example.springauthenticationwithmetamask;

import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class UserRepository {
    private final Map<String, User> users = new ConcurrentHashMap<>();

    public User getUser(String address) {
        return users.computeIfAbsent(address, User::new);
    }
}
