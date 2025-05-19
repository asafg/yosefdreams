package org.yosefdreams.diary.service;

import org.yosefdreams.diary.payload.ChangePasswordDto;

public interface AuthService {

  boolean changePassword(ChangePasswordDto changePasswordDto);
}
