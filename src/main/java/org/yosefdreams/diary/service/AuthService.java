package org.yosefdreams.diary.service;

import org.yosefdreams.diary.payload.LoginDto;

public interface AuthService {
	String login(LoginDto loginDto);
}
