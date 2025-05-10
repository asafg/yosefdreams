package org.yosefdreams.diary.service;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.yosefdreams.diary.payload.SigninDto;
import org.yosefdreams.jwt.JwtTokenProvider;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

  private AuthenticationManager authenticationManager;
  private JwtTokenProvider jwtTokenProvider;

  @Override
  public String signin(SigninDto singinDto) {

    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                singinDto.getUsernameOrEmail(), singinDto.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    String token = jwtTokenProvider.generateToken(authentication);

    return token;
  }
}
