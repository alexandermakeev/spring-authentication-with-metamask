package com.example.springauthenticationwithmetamask;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class MetaMaskAuthenticationRequest extends UsernamePasswordAuthenticationToken {
    public MetaMaskAuthenticationRequest(String address, String signature) {
        super(address, signature);
        super.setAuthenticated(false);
    }

    public String getAddress() {
        return (String) super.getPrincipal();
    }

    public String getSignature() {
        return (String) super.getCredentials();
    }
}
