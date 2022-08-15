package com.example.jwtdemo.controller;

import com.example.jwtdemo.request.JwtAuthenticationRequest;
import com.example.jwtdemo.response.JwtAuthenticationResponse;
import com.example.jwtdemo.service.JwtUserDetailsService;
import com.example.jwtdemo.utils.JwtUtil;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;


@RestController
@CrossOrigin
public class JwtAuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtAuthenticationRequest authenticationRequest) throws Exception {

        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

        final UserDetails userDetails = jwtUserDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());

        final String token = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JwtAuthenticationResponse(token));
    }
    @RequestMapping(value = "/refreshToken", method = RequestMethod.GET)
    public ResponseEntity<?> refreshToken(HttpServletRequest request) throws Exception {
        // From the HttpRequest get the claims
        DefaultClaims defaultClaims = (io.jsonwebtoken.impl.DefaultClaims) request.getAttribute("claims");

        Map<String, Object> claims = new HashMap<>(defaultClaims);
        String token = jwtUtil.generateRefreshToken(claims, claims.get(DefaultClaims.SUBJECT).toString());
        return ResponseEntity.ok(new JwtAuthenticationResponse(token));
    }


    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
