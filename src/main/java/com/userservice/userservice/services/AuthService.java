package com.userservice.userservice.services;

import com.userservice.userservice.dtos.UserDto;
import com.userservice.userservice.models.Session;
import com.userservice.userservice.models.SessionStatus;
import com.userservice.userservice.models.User;
import com.userservice.userservice.repositories.SessionRepository;
import com.userservice.userservice.repositories.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMapAdapter;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class AuthService {
    private UserRepository userRepository;
    private SessionRepository sessionRepository;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public AuthService(UserRepository userRepository, SessionRepository sessionRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public ResponseEntity<UserDto> login(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {  // Checking whether User is not present in DB, If not return null
            return null;
        }

        User user = userOptional.get();

        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {  // Trying to match, user given pw with DB stored pw
            // Throw an exception
            throw new RuntimeException("Wrong Password Entered");
        }

        //Generate the login Token via RandomTokenGenerator
        //String token = RandomStringUtils.randomAlphanumeric(30);

        //Generate the login Token via JWT
        //****************JWT Start****************
        // This is the 1st component of JWT called "Header", Where we can mention which algo to save the data
        MacAlgorithm alg = Jwts.SIG.HS256; //or HS384 or HS256
        SecretKey key = alg.key().build(); // This is the 3rd component of JWT called "Signature/SecretToken"

        // This is the 2nd component of JWT called "Payload", where we can send msg in the JWT Token. So here msg will be some JSON string
        // Below is the HardCoded JSON string
        /*
        String message = "{\n" +
                "   \"email\":\"nikhil9nayak@gmail.com\",\n" +
                "   \"roles\":[\n" +
                "      \"student\"\n" +
                "   ],\n" +
                "   \"expiry\":\"1Jan\"\n" +
                "}";

         */
        // Below is the Dynamic JSON string set as per user data
        Map<String,Object> jsonMap = new HashMap<>();
        jsonMap.put("email", user.getEmail());
        jsonMap.put("roles", List.of(user.getRoles()));
        jsonMap.put("createAt", new Date());
        jsonMap.put("expireAt", DateUtils.addDays(new Date(), 30));


//        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Create the compact JWS: JWS is nothing but JWT Token String
//        String jws = Jwts.builder().content(content, "text/plain").signWith(key, alg).compact();
        String jws = Jwts.builder()
                .claims(jsonMap)
                .signWith(key,alg)
                .compact();

        // Parse the compact JWS:
//        content = Jwts.parser().verifyWith(key).build().parseSignedContent(jws).getPayload();
//        assert message.equals(new String(content, StandardCharsets.UTF_8));

        //****************JWT End****************


        Session session = new Session();
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(jws);
        session.setUser(user);
        sessionRepository.save(session);

        UserDto userDto = new UserDto();
        userDto.setEmail(email);

        MultiValueMapAdapter<String, String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE, "auth-token:" + jws);

        ResponseEntity<UserDto> response = new ResponseEntity<>(userDto, headers, HttpStatus.OK);

        return response;
    }

    public ResponseEntity<Void> logout(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);

        if (sessionOptional.isEmpty()) {
            return null;
        }

        Session session = sessionOptional.get();

        session.setSessionStatus(SessionStatus.ENDED);

        sessionRepository.save(session);

        return ResponseEntity.ok().build();
    }

    public UserDto signUp(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password)); // encrypting the pw and storing in DB

        User savedUser = userRepository.save(user);

        return UserDto.from(savedUser);
    }

    public SessionStatus validate(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);

        if (sessionOptional.isEmpty()) {
            return null;
        }

        return SessionStatus.ACTIVE;
    }

}