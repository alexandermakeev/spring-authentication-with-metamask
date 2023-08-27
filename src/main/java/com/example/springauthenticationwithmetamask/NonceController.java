package com.example.springauthenticationwithmetamask;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NonceController {
    @Autowired
    private UserRepository userRepository;

    @GetMapping("/nonce/{address}")
    public ResponseEntity<Integer> getNonce(@PathVariable String address) {
        User user = userRepository.getUser(address);
        return ResponseEntity.ok(user.getNonce());
    }
}
