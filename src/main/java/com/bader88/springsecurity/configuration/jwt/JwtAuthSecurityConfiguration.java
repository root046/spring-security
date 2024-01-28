package com.bader88.springsecurity.configuration.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Configures basic authentication for the Spring Security framework.
 */
@Configuration
public class JwtAuthSecurityConfiguration {

    /**
     * Creates a new {@link SecurityFilterChain} that enables basic authentication, form login, and disables CSRF protection.
     *
     * @return the new {@link SecurityFilterChain}
     * @throws Exception if an error occurs while building the security filter chain
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Lines 1-4: Configures the security filter chain to require authentication for all requests, except (/authenticate).
        http.authorizeHttpRequests(auth -> {
            auth
                .requestMatchers("/authenticate").permitAll()
                .anyRequest().authenticated();
        });

        // Lines 5-6: Configures the session management to be stateless.
        http.sessionManagement(
                session -> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                )
        );

        // Lines 7-10: Enables form login (/login) and logout (/logout) and sets the default pages and failure URL.
        //http.formLogin(withDefaults());

        // Lines 11-12: Enables HTTP basic authentication and sets the default realm name.
        http.httpBasic(withDefaults());

        // Lines 13-16: Disables CSRF protection.
        http.csrf(csrf -> csrf.disable());

        // Lines 17: Configures the HTTP headers to set X-Frame-Options to same origin.
        http.headers(headers -> headers.frameOptions(
                frameOptionsConfig -> frameOptionsConfig.disable()
                )
        );

        // Configures OAuth 2.0 resource server using JWT.
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));

        // Returns the built security filter chain.
        return http.build();
    }

    /**
     * Configures Cross-Origin Resource Sharing (CORS) for all requests.
     * <p>
     * This allows the client-side code running in the web browser to make cross-origin HTTP requests to the
     * server, which is required for modern web applications that use AJAX calls.
     * <p>
     * By default, all origins are allowed to make cross-origin requests, but this can be restricted to specific
     * origins by modifying the allowedOrigins property.
     */
    //global Configuration to all project
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry
                        .addMapping("/**")
                        .allowedMethods("*")
                        .allowedOrigins("http://localhost:3000");
            }
        };
    }

    //if you want local Configuration to specific Controller, put this annotation of the top of controller you want to use.
    //@CrossOrigin(origins = "http://localhost:3000")

    @Bean
    public DataSource dataSource() {
        // Configures an embedded H2 database as the data source.
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    enum Role {
        USER,
        ADMIN
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {

        /** this will store multiple Credentials details in database(H2)
         *
         */

        var admin = User.withUsername("root")
                .password("0000")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(String.valueOf(Role.ADMIN))
                .build();

        var user = User.withUsername("bader")
                .password("0000")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(String.valueOf(Role.USER))
                .build();

        // Initializes a JdbcUserDetailsManager with the provided data source.
        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(admin);
        jdbcUserDetailsManager.createUser(user);

        return jdbcUserDetailsManager;
    }

    /**
     * Provides a BCryptPasswordEncoder bean for password hashing.
     *
     * @return the configured {@link BCryptPasswordEncoder} bean
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        // Creates a JWKSet with the RSA key.
        var jwkSet = new JWKSet(rsaKey);

        // Returns a JWKSource that selects the provided JWKSet.
        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public KeyPair keyPair() {
        try {
            // Generates a new RSA key pair.
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        // Creates an RSAKey with the provided RSA public and private keys.
        return new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        // Creates a JWT decoder with the provided RSA key.
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();

    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // Creates a JWT encoder with the provided JWK source.
        return new NimbusJwtEncoder(jwkSource);
    }
}