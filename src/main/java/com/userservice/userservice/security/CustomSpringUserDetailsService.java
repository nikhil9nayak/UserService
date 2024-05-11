package com.userservice.userservice.security;

import com.userservice.userservice.models.User;
import com.userservice.userservice.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomSpringUserDetailsService implements UserDetailsService { // instead of fetching default username and pw from default InMemory when a user login, we will implement our own CustomSpringUserDetail class to fetch the user details from DB

    private UserRepository userRepository;

    CustomSpringUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Fetch the user wit the given username from DB
        Optional<User> optionalUser = userRepository.findByEmail(username);

        if(optionalUser.isEmpty()){
            throw new UsernameNotFoundException("User with the given username doesn't exist.");

        }

        User user = optionalUser.get();

        return new CustomUserDetails(user);
    }

}
