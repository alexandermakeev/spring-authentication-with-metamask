package com.example.springauthenticationwithmetamask;

import org.springframework.security.core.userdetails.User;

import java.util.Collections;

public class MetaMaskUserDetails extends User {
    private final Integer nonce;

    public MetaMaskUserDetails(String address, String signature, Integer nonce) {
        super(address, signature, Collections.emptyList());
        this.nonce = nonce;
    }

    public String getAddress() {
        return getUsername();
    }

    public Integer getNonce() {
        return nonce;
    }
}
