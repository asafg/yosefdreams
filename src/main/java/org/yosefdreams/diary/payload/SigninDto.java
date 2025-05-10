package org.yosefdreams.diary.payload;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class SigninDto {
  private String usernameOrEmail;
  private String password;
}
