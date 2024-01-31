package com.bader88.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/role/v1") // Base mapping for all endpoints in this controller
public class RoleControllerV1 {

    // Endpoint accessible to anyone
    @GetMapping("/guest")
    public String AnyOneCanCallMe() {
        return "welcome guest";
    }

    // Endpoint accessible only to ADMIN role
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String JustAdminCanCallMe() {
        return "welcome admin";
    }

    // Endpoint accessible only to USER role
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String JustUserCanCallMe() {
        return "welcome user";
    }

    // Endpoint accessible to either USER or ADMIN roles
    @GetMapping("/registered")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String AllUsersCanCallMe() {
        return "welcome registered user !";
    }

}