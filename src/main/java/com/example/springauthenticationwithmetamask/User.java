package com.example.springauthenticationwithmetamask;

import lombok.Getter;

@Getter
public class User {
    private final String address;
    private Integer nonce;

    public User(String address) {
        this.address = address;
        this.changeNonce();
    }

    public User(String address, Integer nonce) {
        this.address = address;
        this.nonce = nonce;
    }

    public void changeNonce() {
        this.nonce = (int) (Math.random() * 1000000);
    }
}
