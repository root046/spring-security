package com.bader88.springsecurity.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/role/v4") // Base mapping for all endpoints in this controller
public class RoleControllerV4 {

    @GetMapping("/guest")
    public String AnyOneCanCallMe() {
        return "welcome guest"; // Returns a welcome message for any one
    }

    @GetMapping("/admin/{username}")
    @Secured("ROLE_ADMIN")
    public String JustAdminWithRealUsernameCanCallMe(@PathVariable String username) {
        return "welcome : " + username; // Returns a welcome message for admin users
    }

    @GetMapping("/Specific-admin/{username}")
    @Secured("ROLE_ADMIN")
    @PostAuthorize("returnObject == 'root'") // Specifies post-authorization rules, ensuring that the returned value equals 'root'
    public String JustSpecificAdminCanCallMe(@PathVariable String username) {
        return username;
    }


    @GetMapping("/user/{username}")
    @Secured("ROLE_USER")
    public String JustUserWithRealUsernameCanCallMe(@PathVariable String username) {
        return "welcome : " + username; // Returns a welcome message for regular users
    }

    @GetMapping("/registered/{username}")
    @Secured({"ROLE_USER", "ROLE_ADMIN"})
    public String AllUsersCanCallMe(@PathVariable String username, Authentication authentication) {
        return "You are registered as     : " + authentication.getName() // Returns the currently authenticated user's name
                + "\nand your path variable is : " + username; // Returns the path variable 'username'
    }
}