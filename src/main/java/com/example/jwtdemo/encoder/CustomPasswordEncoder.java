package com.example.jwtdemo.encoder;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Component
public class CustomPasswordEncoder implements PasswordEncoder {

    public String getSHA(String input){

        String encodedValue = "";
        try {
            /* MessageDigest instance for hashing using SHA512*/
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            /* digest() method called to calculate message digest of an input and return array of byte */
            encodedValue = toHexString(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        }
        catch(NoSuchAlgorithmException nsae) {

        }
        return encodedValue;
    }
    public static String toHexString(byte[] hash){
        /* Convert byte array of hash into digest */
        BigInteger number = new BigInteger(1, hash);

        /* Convert the digest into hex value */
        StringBuilder hexString = new StringBuilder(number.toString(16));

        /* Pad with leading zeros */
        while (hexString.length() < 32){
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }
    @Override
    public String encode(CharSequence rawPassword) {
        // TODO Auto-generated method stub
        return getSHA(rawPassword.toString());
    }
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // TODO Auto-generated method stub


        return encodedPassword.equals(getSHA(rawPassword.toString()));
    }
}
