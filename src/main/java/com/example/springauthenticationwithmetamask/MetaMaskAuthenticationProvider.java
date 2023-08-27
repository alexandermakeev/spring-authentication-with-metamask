package com.example.springauthenticationwithmetamask;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;

@Component
public class MetaMaskAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    @Autowired
    private UserRepository userRepository;

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        MetaMaskAuthenticationRequest metamaskAuthenticationRequest = (MetaMaskAuthenticationRequest) authentication;
        MetaMaskUserDetails metamaskUserDetails = (MetaMaskUserDetails) userDetails;

        if (!isSignatureValid(authentication.getCredentials().toString(),
                metamaskAuthenticationRequest.getAddress(), metamaskUserDetails.getNonce())) {
            logger.debug("Authentication failed: signature is not valid");
            throw new BadCredentialsException("Signature is not valid");
        }
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        MetaMaskAuthenticationRequest auth = (MetaMaskAuthenticationRequest) authentication;
        User user = userRepository.getUser(auth.getAddress());
        return new MetaMaskUserDetails(auth.getAddress(), auth.getSignature(), user.getNonce());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == MetaMaskAuthenticationRequest.class;
    }

    public boolean isSignatureValid(String signature, String address, Integer nonce) {
        // Compose the message with nonce
        String message = "Signing a message to login: %s".formatted(nonce);

        // Extract the ‘r’, ‘s’ and ‘v’ components
        byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
        byte v = signatureBytes[64];
        if (v < 27) {
            v += 27;
        }
        byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
        byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);
        Sign.SignatureData data = new Sign.SignatureData(v, r, s);

        // Retrieve public key
        BigInteger publicKey;
        try {
            publicKey = Sign.signedPrefixedMessageToKey(message.getBytes(), data);
        } catch (SignatureException e) {
            logger.debug("Failed to recover public key", e);
            return false;
        }

        // Get recovered address and compare with the initial address
        String recoveredAddress = "0x" + Keys.getAddress(publicKey);
        return address.equalsIgnoreCase(recoveredAddress);
    }
}
