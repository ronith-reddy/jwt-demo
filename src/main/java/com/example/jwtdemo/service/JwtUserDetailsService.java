package com.example.jwtdemo.service;

import com.example.jwtdemo.dao.UserDao;
import com.example.jwtdemo.encoder.CustomPasswordEncoder;
import com.example.jwtdemo.entity.UserCredentials;
import com.example.jwtdemo.request.NewUserRequestEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private UserDao userDao;
    @Autowired
    private CustomPasswordEncoder customPasswordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserCredentials userCredentials = userDao.findByUsername(username);
        if (userCredentials == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        return new org.springframework.security.core.userdetails.User(userCredentials.getUsername(), userCredentials.getPassword(),
                new ArrayList<>());
    }

    public UserCredentials registerUser(NewUserRequestEntry newUserRequestEntry) {
        UserCredentials userCredentials = new UserCredentials();
        userCredentials.setUsername(newUserRequestEntry.getUsername());
        userCredentials.setPassword(customPasswordEncoder.encode(newUserRequestEntry.getPassword()));
        return userDao.save(userCredentials);
    }
}
