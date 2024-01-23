package com.bader88.springsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWordResource {
    @GetMapping("/hello-world")
    public String HelloWorld() {
        return "Hello World";
    }

}
