package com.bader88.springsecurity.controller;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/role/v2") // Base mapping for all endpoints in this controller
public class RoleControllerV2 {

    @GetMapping("/guest")
    public String AnyOneCanCallMe() {
        return "welcome guest"; // Returns a welcome message for any one
    }

    @GetMapping("/admin/{username}")
    @PreAuthorize("hasRole('ADMIN') and #username == authentication.name") // Specifies pre-authorization rules, allowing only admins to access this endpoint with their own username
    public String JustAdminWithRealUsernameCanCallMe(@PathVariable String username) {
        return "welcome : " + username; // Returns a welcome message for admin users
    }

    @GetMapping("/Specific-admin/{username}")
    @PreAuthorize("hasRole('ADMIN') and #username == authentication.name") // Specifies pre-authorization rules, allowing only admins to access this endpoint with their own username
//    @PreAuthorize("hasRole('ADMIN') and #username == 'root'") // you can use this to just specific admin users call it
    @PostAuthorize("returnObject == 'root'") // Specifies post-authorization rules, ensuring that the returned value equals 'root'
    public String JustSpecificAdminCanCallMe(@PathVariable String username) {
        return username;
    }


    @GetMapping("/user/{username}")
    @PreAuthorize("hasRole('USER') and #username == authentication.name") // Specifies pre-authorization rules, allowing only user to access this endpoint with their own username
    public String JustUserWithRealUsernameCanCallMe(@PathVariable String username) {
        return "welcome : " + username; // Returns a welcome message for regular users
    }

    @GetMapping("/registered/{username}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')") // Specifies pre-authorization rules, allowing both users and admins to access this endpoint
    public String AllUsersCanCallMe(@PathVariable String username, Authentication authentication) {
        return "You are registered as     : " + authentication.getName() // Returns the currently authenticated user's name
                + "\nand your path variable is : " + username; // Returns the path variable 'username'
    }
}