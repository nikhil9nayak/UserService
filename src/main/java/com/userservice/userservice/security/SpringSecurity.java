package com.userservice.userservice.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration // Instead of using annotation based configurations(Component, Autowired etc), We can create our own configurations and perform Dependency Injections also (https://www.youtube.com/watch?v=hYky8HEaTCk)
public class SpringSecurity {

    @Bean //telling spring to create an obj of below class
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
