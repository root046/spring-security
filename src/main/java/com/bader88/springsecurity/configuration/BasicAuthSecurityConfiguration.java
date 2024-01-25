package com.bader88.springsecurity.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Configures basic authentication for the Spring Security framework.
 */
@Configuration
public class BasicAuthSecurityConfiguration {

    /**
     * Creates a new {@link SecurityFilterChain} that enables basic authentication, form login, and disables CSRF protection.
     *
     * @return the new {@link SecurityFilterChain}
     * @throws Exception if an error occurs while building the security filter chain
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Lines 1-4: Configures the security filter chain to require authentication for all requests.
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

        // Lines 5-6: Configures the session management to be stateless.
        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Lines 7-10: Enables form login (/login) and logout (/logout) and sets the default pages and failure URL.
        //http.formLogin(withDefaults());

        // Lines 11-12: Enables HTTP basic authentication and sets the default realm name.
        http.httpBasic(withDefaults());

        // Lines 13-16: Disables CSRF protection.
        http.csrf(csrf -> csrf.disable());

        // Returns the built security filter chain.
        return http.build();
    }
}