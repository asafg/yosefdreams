package org.yosefdreams.diary.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;

import java.util.Collections;

import org.yosefdreams.diary.entity.Role;
import org.yosefdreams.diary.entity.User;
import org.yosefdreams.diary.payload.SigninDto;
import org.yosefdreams.diary.payload.SignupDto;
import org.yosefdreams.diary.service.AuthService;
import org.yosefdreams.diary.repository.RoleRepository;
import org.yosefdreams.diary.repository.UserRepository;
import org.yosefdreams.jwt.JwtAuthResponse;

/*
import org.yosefdreams.diary.test.entity.Role;
import org.yosefdreams.diary.test.entity.User;
import org.yosefdreams.diary.test.payload.LoginDto;
import org.yosefdreams.diary.test.payload.SignupDto;
import org.yosefdreams.diary.test.repository.RoleRepository;
import org.yosefdreams.diary.test.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
*/
import lombok.AllArgsConstructor;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthService authService;
    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;

    // Build Login REST API
    @PostMapping("/signin")
    public ResponseEntity<JwtAuthResponse> signin(@RequestBody SigninDto singinDto){
        String token = authService.signin(singinDto);

        JwtAuthResponse jwtAuthResponse = new JwtAuthResponse();
        jwtAuthResponse.setAccessToken(token);

        return new ResponseEntity<>(jwtAuthResponse, HttpStatus.OK);
    }
    
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@RequestBody SignupDto signupDto) {

		// add check for username exists in a DB
		if (userRepository.existsByUsername(signupDto.getUsername())) {
			return new ResponseEntity<>("Username is already taken!",
					HttpStatus.BAD_REQUEST);
		}

		// add check for email exists in DB
		if (userRepository.existsByEmail(signupDto.getEmail())) {
			return new ResponseEntity<>("Email is already taken!",
					HttpStatus.BAD_REQUEST);
		}

		// create user object
		User user = new User();
		user.setName(signupDto.getName());
		user.setUsername(signupDto.getUsername());
		user.setEmail(signupDto.getEmail());
		user.setַַPlainTextPassword(signupDto.getPassword());

		Role roles = roleRepository.findByName("ROLE_USER").get();
		user.setRoles(Collections.singleton(roles));

		userRepository.save(user);

		return new ResponseEntity<>("User registered successfully",
				HttpStatus.OK);

	}
}