package com.example.springauthenticationwithmetamask;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

public class MetaMaskAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final UserRepository userRepository;

    public MetaMaskAuthenticationSuccessHandler(UserRepository userRepository) {
        super("/");
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {
        super.onAuthenticationSuccess(request, response, authentication);
        MetaMaskUserDetails principal = (MetaMaskUserDetails) authentication.getPrincipal();
        User user = userRepository.getUser(principal.getAddress());
        user.changeNonce();
    }
}
