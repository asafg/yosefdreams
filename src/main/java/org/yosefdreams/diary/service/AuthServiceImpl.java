package org.yosefdreams.diary.service;

import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.yosefdreams.diary.payload.ChangePasswordDto;

@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

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
