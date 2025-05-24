package org.yosefdreams.diary.controller;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yosefdreams.diary.entity.Role;
import org.yosefdreams.diary.entity.User;
import org.yosefdreams.diary.jwt.JwtAuthResponse;
import org.yosefdreams.diary.jwt.JwtTokenProvider;
import org.yosefdreams.diary.payload.SigninDto;
import org.yosefdreams.diary.payload.SignupDto;
import org.yosefdreams.diary.repository.RoleRepository;
import org.yosefdreams.diary.repository.UserRepository;
import org.yosefdreams.diary.utils.Hash;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
  public static final int RESET_TOKEN_MAX_AGE_MINUTES = 15;

  @Autowired private AuthenticationManager authenticationManager;
  @Autowired private JwtTokenProvider jwtTokenProvider;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;

  public AuthController() {}

  // Build Login REST API
  @PostMapping("/signin")
  public ResponseEntity<JwtAuthResponse> signin(@RequestBody SigninDto singinDto) {
    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                singinDto.getUsernameOrEmail(), singinDto.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    String token = jwtTokenProvider.generateToken(authentication);

    JwtAuthResponse jwtAuthResponse = new JwtAuthResponse();
    jwtAuthResponse.setAccessToken(token);

    return new ResponseEntity<>(jwtAuthResponse, HttpStatus.OK);
  }

  /**
   * User signup (registration)
   *
   * @param signupDto contains necessary user details (username, password and email)
   * @return ResponseEntity with HttpStatus.OK for successful user signup or HttpStatus.BAD_REQUEST
   *     otherwise.
   */
  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@RequestBody SignupDto signupDto) {

    // make sure username is not already taken.
    if (userRepository.existsByUsername(signupDto.getUsername())) {
      return new ResponseEntity<>("Username is already taken!", HttpStatus.BAD_REQUEST);
    }

    // make sure email is not already taken.
    if (userRepository.existsByEmail(signupDto.getEmail())) {
      return new ResponseEntity<>("Email is already taken!", HttpStatus.BAD_REQUEST);
    }

    // create user object
    User user = new User();
    user.setName(signupDto.getName());
    user.setUsername(signupDto.getUsername());
    user.setEmail(signupDto.getEmail());
    user.setַַPlainTextPassword(signupDto.getPassword());

    // Get plain user role from the database
    // and set it to the newly created user
    Role userRole = roleRepository.findByName("ROLE_USER").get();
    user.setRoles(Collections.singleton(userRole));

    userRepository.save(user);

    return new ResponseEntity<>("User registered successfully", HttpStatus.OK);
  }

  @PostMapping("/forgot-password")
  public ResponseEntity<?> forgotPasseord(@RequestBody String email) {

    // add check for username exists in a DB
    Optional<User> userOptional = userRepository.findByEmail(email);
    logger.info("userOptional is empty? " + userOptional.isEmpty());
    if (userOptional.isPresent()) {
      User user = userOptional.get();
      String resetToken = generateResetToken();
      // TODO: replace debug print with actual sending of the reset token via email.
      logger.info("resetToken: " + resetToken);
      // We don't keep the token itself, but its hash so that the token would not leak accidentally.
      String hashedResetToken = Hash.hashString(resetToken);
      user.setResetToken(hashedResetToken);
      user.setResetTokenCreationDate(LocalDateTime.now());
      userRepository.save(user);
    }

    return new ResponseEntity<>(
        "If your email is found in our database, a reset message would be sent to your email address",
        HttpStatus.OK);
  }

  /**
   * Generate unique token. You may add multiple parameters to create a strong token.
   *
   * @return unique token
   */
  private String generateResetToken() {
    StringBuilder token = new StringBuilder();

    return token
        .append(UUID.randomUUID().toString())
        .append(UUID.randomUUID().toString())
        .toString();
  }

  /**
   * Check whether the created token expired or not.
   *
   * @param tokenCreationDate
   * @return true or false
   */
  private boolean isTokenExpired(final LocalDateTime tokenCreationDate) {

    LocalDateTime now = LocalDateTime.now();
    Duration diff = Duration.between(tokenCreationDate, now);

    return diff.toMinutes() >= RESET_TOKEN_MAX_AGE_MINUTES;
  }
}
