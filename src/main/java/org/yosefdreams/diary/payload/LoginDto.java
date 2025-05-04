package org.yosefdreams.diary.payload;

import lombok.Data;

@Data
public class LoginDto {
	private String usernameOrEmail;
    private String password;
}
