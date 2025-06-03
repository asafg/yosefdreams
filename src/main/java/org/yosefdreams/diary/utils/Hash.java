package org.yosefdreams.diary.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class Hash {

  /** According the documentation BCryptPasswordEncoder range is between 4 to 31 */
  private static final int BCRYPT_PASSWORD_ENCODER_STRENGTH = 16;

  public static String hashString(String plainText) {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCRYPT_PASSWORD_ENCODER_STRENGTH);
    // According to
    // https://docs.spring.io/spring-security/site/docs/5.3.0.RELEASE/reference/html5/#authentication-password-storage
    // a prefix of the password encoder being used should be added to the hash
    // in order to allow identify the password encoder that created this hash.
    return "{bcrypt}" + encoder.encode(plainText);
  }
}
