package org.yosefdreams.diary.test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.yosefdreams.diary.jwt.JwtTokenProvider;

@SpringBootTest
@org.springframework.test.context.ActiveProfiles("test")
public class JwtTokenProviderTest {

  @Autowired private JwtTokenProvider jwtTokenProvider;

  @Test
  public void testGenerateAndValidateToken() {
    Authentication auth = new UsernamePasswordAuthenticationToken("testuser", null, null);
    String token = jwtTokenProvider.generateToken(auth);
    assertNotNull(token);
    assertTrue(jwtTokenProvider.validateToken(token));
    String username = jwtTokenProvider.getUsername(token);
    assertEquals("testuser", username);
  }
}
