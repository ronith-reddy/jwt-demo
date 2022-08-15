package com.example.jwtdemo.controller;

import com.example.jwtdemo.request.NewUserRequestEntry;
import com.example.jwtdemo.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> registerUser(@RequestBody NewUserRequestEntry newUserRequestEntry) {
        return ResponseEntity.ok(userDetailsService.registerUser(newUserRequestEntry));
    }
}
