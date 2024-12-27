package com.misha.keycloak;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {


    @GetMapping
    @PreAuthorize("hasRole('client_user')")
    public String hello() {
        return "Hello from USER";
    }

    @GetMapping("/hello-2")
    @PreAuthorize("hasRole('client_admin')")
    public String hello2() {
        return "Hello from AMDIN";
    }
}

