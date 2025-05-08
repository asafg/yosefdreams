package org.yosefdreams.diary;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.yosefdreams.jwt.JwtTokenProvider;

@SpringBootTest
public class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Test
    public void contextLoads() {
        assertNotNull(jwtTokenProvider);
    }
}
