package com.example.jwtdemo.dao;

import com.example.jwtdemo.entity.UserCredentials;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao extends CrudRepository<UserCredentials, Integer> {

    UserCredentials findByUsername(String username);
}