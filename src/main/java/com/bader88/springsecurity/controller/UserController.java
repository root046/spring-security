package com.bader88.springsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    // Endpoint accessible only to USER role
    // just for (/users)
    @GetMapping("/users")
    public String JustUserCanCallMe(Authentication authentication) {
        return authentication.getName();
    }

}
