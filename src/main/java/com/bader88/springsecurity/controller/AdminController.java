package com.bader88.springsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
    // All Endpoint start with (/admin) can accessible only to ADMIN role

    @GetMapping("/admin")
    public String JustAdminCanCallMe(Authentication authentication) {
        return authentication.getName();
    }
    @GetMapping("/admin/test")
    public String JustUserCanCallMe2(Authentication authentication) {
        return authentication.getName();
    }
}
