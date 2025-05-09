package org.yosefdreams.diary.service;

import org.yosefdreams.diary.payload.SigninDto;

public interface AuthService {
	String signin(SigninDto singinDto);
}
