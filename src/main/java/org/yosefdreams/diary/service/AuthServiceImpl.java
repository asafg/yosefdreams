package org.yosefdreams.diary.service;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.yosefdreams.diary.jwt.JwtTokenProvider;
import org.yosefdreams.diary.payload.ChangePasswordDto;
import org.yosefdreams.diary.repository.UserRepository;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

  private AuthenticationManager authenticationManager;
  private JwtTokenProvider jwtTokenProvider;
  private UserRepository userRepository;

  @Override
  public boolean changePassword(ChangePasswordDto changePasswordDto) {
    //  User user =
    // TODO Auto-generated method stub
    return false;
  }

  // TODO: this code is taken from copilot, check whether we need it the way it is
  private boolean verifyResetToken(String rawToken, String hashedToken) {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    return encoder.matches(rawToken, hashedToken);
  }
}
