package com.security.spring_jwt_demo.service;

import com.security.spring_jwt_demo.dto.LoginRequest;
import com.security.spring_jwt_demo.dto.LoginResponse;
import com.security.spring_jwt_demo.dto.RegisterRequest;
import com.security.spring_jwt_demo.model.Role;
import com.security.spring_jwt_demo.model.User;
import com.security.spring_jwt_demo.repository.RoleRepository;
import com.security.spring_jwt_demo.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    public AuthService(AuthenticationManager authenticationManager, JwtService jwtService, UserRepository userRepository, BCryptPasswordEncoder passwordEncoder, RoleRepository roleRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
    }

    public LoginResponse login(LoginRequest loginRequest) {
        // Maybe you can fetch the details in the database then check if exist, and include the roles in UsernamePaswwordAuthToken

        // Authenticate the user
        Authentication authentication = authenticationManager
                .authenticate(
                        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
                );

        // Generate JWT token
        String token = jwtService.generateToken((UserDetails) authentication.getPrincipal());
        // Return Token
        return new LoginResponse(token);
    }

    public String register(RegisterRequest registerRequest) {
        if (userRepository.findUserByUsername(registerRequest.getUsername()).isPresent()) {
            return "Username already in use";
        }

        if (registerRequest.getRoles() == null || registerRequest.getRoles().isEmpty()) {
            registerRequest.setRoles(Set.of("USER"));
        }

        Set<Role> userRoles = registerRequest.getRoles().stream()
                .map(roleName -> roleRepository.findByName(roleName)
                        .orElseThrow(() -> new RuntimeException("Role not found: " + roleName)))
                .collect(Collectors.toSet());

        String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());

        User newUser = new User(registerRequest.getUsername(), encodedPassword, userRoles);
        userRepository.save(newUser);

        return "Member registered successfully";
    }

}
