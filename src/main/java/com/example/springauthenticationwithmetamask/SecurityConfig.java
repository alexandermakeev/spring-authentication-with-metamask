package com.example.springauthenticationwithmetamask;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private UserRepository userRepository;

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> myAuthenticationProviders) {
        return new ProviderManager(myAuthenticationProviders);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        return http
                .authorizeHttpRequests(customizer -> customizer
                        .requestMatchers(HttpMethod.GET, "/nonce/*").permitAll()
                        .anyRequest().authenticated())
                .formLogin(customizer -> customizer.loginPage("/login")
                        .failureUrl("/login?error=true")
                        .permitAll())
                .logout(customizer -> customizer.logoutUrl("/logout"))
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(authenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    private MetaMaskAuthenticationFilter authenticationFilter(AuthenticationManager authenticationManager) {
        MetaMaskAuthenticationFilter filter = new MetaMaskAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(new MetaMaskAuthenticationSuccessHandler(userRepository));
        filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true"));
        filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        return filter;
    }
}
