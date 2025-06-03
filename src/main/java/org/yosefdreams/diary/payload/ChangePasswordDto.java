package org.yosefdreams.diary.payload;

import lombok.Data;

@Data
public class ChangePasswordDto {
  private String email;
  private String newPassword;
  /** Plain text Reset Token */
  private String resetToken;
}
