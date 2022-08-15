package com.example.jwtdemo.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class NewUserRequestEntry {

    private String username;
    private String password;
}
