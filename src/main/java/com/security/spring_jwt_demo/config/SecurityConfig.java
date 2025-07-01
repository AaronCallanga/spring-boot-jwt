package com.security.spring_jwt_demo.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Configuration
public class SecurityConfig {
    // For Symmetric key
    @Value("${security.jwt.secret}")
    private String secretKey;

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] secretBytes = Base64.getDecoder().decode(secretKey.getBytes());
        SecretKey hmacKey = new SecretKeySpec(secretBytes, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(hmacKey).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        byte[] secretBytes = Base64.getDecoder().decode(secretKey.getBytes());
        SecretKey hmacKey = new SecretKeySpec(secretBytes, "HmacSHA256");
        return new NimbusJwtEncoder(new ImmutableSecret<>(hmacKey));
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/api/v1/auth/**").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }
}
