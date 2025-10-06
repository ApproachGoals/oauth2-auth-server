package com.swc.authserver;

import com.swc.authserver.entities.User;
import com.swc.authserver.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class BCryptPasswordTester {
    private String cryptedText = "$2a$10$6LJwArMxchpOHyOICxEK7uG5NqEPzVHjeZECy2smo3ro4Bahjg3Pa";
    @Autowired
    private UserRepository userRepository;

    @Test
    public void passwordEncrypt(){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encryptedPassword = encoder.encode("123456");
        Optional<User> user = userRepository.findByUsername("sa");

        System.out.println(encryptedPassword);
        assertTrue(encoder.matches("123456", user.get().getPassword()));
    }



}
