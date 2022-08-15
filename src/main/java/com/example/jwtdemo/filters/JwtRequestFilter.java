package com.example.jwtdemo.filters;

import com.example.jwtdemo.service.JwtUserDetailsService;
import com.example.jwtdemo.utils.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.example.jwtdemo.constants.RequestHeader.IS_REFRESH_TOKEN;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {


    public static final String AUTH_HEADER_KEY = "Authorization";

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader(AUTH_HEADER_KEY);

        String username = null;
        String jwtToken = null;

        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        try {
            if (containsBearerToken(authHeader)) {
                jwtToken = authHeader.substring(7);
                username = getUserNameFromToken(jwtToken);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                    UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

                    if (jwtUtil.validateToken(jwtToken, userDetails)) {
                        setSpringSecurityContextAuthentication(request, userDetails);
                    }
                }
            } else {
                logger.warn("JWT Token does not begin with Bearer String");
            }
        } catch (ExpiredJwtException ex) {
            String isRefreshToken = request.getHeader(IS_REFRESH_TOKEN.getHeaderName());
            String requestURL = request.getRequestURL().toString();

            if (validateTokenRefreshing(isRefreshToken, requestURL)) {
                allowTokenRefresh(ex, request);
            } else {
                request.setAttribute("exception", ex);
            }
        }


        filterChain.doFilter(request, response);
    }

    private static boolean validateTokenRefreshing(String isRefreshToken, String requestURL) {
        return Boolean.parseBoolean(isRefreshToken) && requestURL.contains("refreshToken");
    }

    private static void setSpringSecurityContextAuthentication(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

    private String getUserNameFromToken(String jwtToken) {
        try {
            return jwtUtil.getUsernameFromToken(jwtToken);
        } catch (IllegalArgumentException e) {
            System.out.println("Unable to get JWT Token");
            throw e;
        } catch (ExpiredJwtException e) {
            System.out.println("JWT Token has expired");
            throw e;
        }
    }

    private static boolean containsBearerToken(String authHeader) {
        return authHeader != null && authHeader.startsWith("Bearer ");
    }

    private void allowTokenRefresh(ExpiredJwtException ex, HttpServletRequest request) {

        // create a UsernamePasswordAuthenticationToken with null values.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                null, null, null);
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        // Set the claims so that in controller we will be using it to create
        // new JWT
        request.setAttribute("claims", ex.getClaims());

    }
}
