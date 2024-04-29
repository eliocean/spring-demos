package org.eli.springsecurity.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Auth {
    @PostMapping("/login")
    public String login(){
        return  "login success";
    }
}
