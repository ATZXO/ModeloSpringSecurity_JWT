package com.atz.security.controller;

import com.atz.security.controller.dto.AuthCreateUserRequest;
import com.atz.security.controller.dto.AuthLoginRequest;
import com.atz.security.controller.dto.AuthResponse;
import com.atz.security.service.impl.UserDetailServiceImpl;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final UserDetailServiceImpl userDetailService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthLoginRequest userRequest){
        return new ResponseEntity<>(this.userDetailService.loginUser(userRequest), HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody AuthCreateUserRequest userCreateRequest){
        return new ResponseEntity<>(this.userDetailService.registerUser(userCreateRequest), HttpStatus.CREATED);
    }
}
