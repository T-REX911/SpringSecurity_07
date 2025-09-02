package com.smartech.SpringSecurity_07.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/pages")
public class LoginController {
    @GetMapping
    public String login(){
        return "Welcome";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminLogin(){
        return ResponseEntity.ok("Welcome Admin");
    }
}
