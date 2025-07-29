package org.yosefdreams.diary.service;

import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.yosefdreams.diary.entity.User;
import org.yosefdreams.diary.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {
  private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

  private UserRepository userRepository;

  public CustomUserDetailsService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
    logger.debug("loadUserByUsername called with: {}", usernameOrEmail);
    User user =
        userRepository
            .findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
            .orElseThrow(
                () ->
                    new UsernameNotFoundException(
                        "User not found with username or email: " + usernameOrEmail));
    logger.debug(
        "Found user: username={}, email={}, password={}",
        user.getUsername(),
        user.getEmail(),
        user.getPassword());
    Set<GrantedAuthority> authorities =
        user.getRoles()
            .stream()
            .map((role) -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toSet());
    logger.debug(
        "Returning UserDetails with username={}, password={}",
        user.getUsername(),
        user.getPassword());
    return new org.springframework.security.core.userdetails.User(
        user.getUsername(), user.getPassword(), authorities);
  }
}
