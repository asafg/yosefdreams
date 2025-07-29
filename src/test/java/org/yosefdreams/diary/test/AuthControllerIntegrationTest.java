package org.yosefdreams.diary.test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.yosefdreams.diary.entity.Role;
import org.yosefdreams.diary.entity.User;
import org.yosefdreams.diary.repository.UserRepository;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
public class AuthControllerIntegrationTest {

  private static final String TEST_USER_EMAIL = "test@example.com";
  private static final String TEST_USER_PASSWORD = "password123";
  private static final String TEST_USER_USERNAME = "testuser";

  @Container
  private static final MySQLContainer<?> MYSQL_CONTAINER =
      new MySQLContainer<>("mysql:8.0")
          .withDatabaseName("yosef_test")
          .withUsername("testuser")
          .withPassword("testpass")
          .withReuse(true);

  @Autowired private MockMvc mockMvc;

  @Autowired private UserRepository userRepository;

  @Autowired private PasswordEncoder passwordEncoder;

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", MYSQL_CONTAINER::getJdbcUrl);
    registry.add("spring.datasource.username", MYSQL_CONTAINER::getUsername);
    registry.add("spring.datasource.password", MYSQL_CONTAINER::getPassword);
    registry.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");

    // Add JWT properties
    registry.add("app.jwt.secret", () -> "testSecretKey12345678901234567890123456789012");
    registry.add("app.jwt.expiration.milliseconds", () -> "604800000");
  }

  @BeforeEach
  void setup() {
    // Clear and recreate test user before each test
    userRepository.deleteAll();

    // Create and save a role
    Role userRole = new Role();
    userRole.setName("ROLE_USER");

    // Create and save test user with the role
    User user = new User();
    user.setUsername(TEST_USER_USERNAME);
    user.setEmail(TEST_USER_EMAIL);
    user.setPassword(passwordEncoder.encode(TEST_USER_PASSWORD));
    user.setRoles(Set.of(userRole));
    userRepository.save(user);
  }

  @Test
  public void testSignIn_Success() throws Exception {
    String loginRequest =
        String.format(
            "{\"usernameOrEmail\":\"%s\",\"password\":\"%s\"}",
            TEST_USER_EMAIL, TEST_USER_PASSWORD);

    mockMvc
        .perform(
            post("/api/auth/signin").contentType(MediaType.APPLICATION_JSON).content(loginRequest))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.tokenType").value("Bearer"))
        .andExpect(jsonPath("$.accessToken").exists())
        .andExpect(jsonPath("$.username").value(TEST_USER_USERNAME));
  }

  @Test
  public void testSignIn_InvalidCredentials() throws Exception {
    String loginRequest =
        "{\"usernameOrEmail\":\"test@example.com\",\"password\":\"wrongpassword\"}";

    mockMvc
        .perform(
            post("/api/auth/signin").contentType(MediaType.APPLICATION_JSON).content(loginRequest))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Bad credentials"));
  }

  @Test
  public void testSignIn_UserNotFound() throws Exception {
    String loginRequest =
        "{\"usernameOrEmail\":\"nonexistent@example.com\",\"password\":\"password\"}";

    mockMvc
        .perform(
            post("/api/auth/signin").contentType(MediaType.APPLICATION_JSON).content(loginRequest))
        .andExpect(status().isUnauthorized())
        .andExpect(
            jsonPath("$.message")
                .value("User not found with email/username: nonexistent@example.com"));
  }

  @Test
  public void testSignIn_MissingFields() throws Exception {
    // Missing password
    String loginRequest = "{\"usernameOrEmail\":\"test@example.com\"}";

    mockMvc
        .perform(
            post("/api/auth/signin").contentType(MediaType.APPLICATION_JSON).content(loginRequest))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.password").value("must not be empty"));

    // Missing username/email
    loginRequest = "{\"password\":\"password123\"}";
    mockMvc
        .perform(
            post("/api/auth/signin").contentType(MediaType.APPLICATION_JSON).content(loginRequest))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.usernameOrEmail").value("must not be empty"));
  }
}
