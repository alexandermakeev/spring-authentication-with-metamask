package com.example.springauthenticationwithmetamask;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class MetaMaskAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String SPRING_SECURITY_FORM_ADDRESS = "address";
    public static final String SPRING_SECURITY_FORM_SIGNATURE = "signature";

    protected MetaMaskAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        UsernamePasswordAuthenticationToken authRequest = getAuthRequest(request);
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) {
        String address = obtainAddress(request);
        String signature = obtainSignature(request);

        if (address == null) {
            address = "";
        }
        if (signature == null) {
            signature = "";
        }

        return new MetaMaskAuthenticationRequest(address, signature);
    }

    private String obtainAddress(HttpServletRequest request) {
        return request.getParameter(SPRING_SECURITY_FORM_ADDRESS);
    }

    private String obtainSignature(HttpServletRequest request) {
        return request.getParameter(SPRING_SECURITY_FORM_SIGNATURE);
    }
}
