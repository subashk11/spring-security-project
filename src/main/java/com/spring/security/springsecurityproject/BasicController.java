package com.spring.security.springsecurityproject;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BasicController {

    @GetMapping("/hello")
    public String helloWorld(){
        return "hello world!";
    }

    // PREAUTHORIZE IS USED TO RESTRICT ACCESS TO THE API BASED ON ROLE BASE ACCESS. WITH A METHOD TO VALIDATE
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String getUser(){
        return "Hello, from User";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String getAdmin(){
        return "Hello, from admin";
    }
}
