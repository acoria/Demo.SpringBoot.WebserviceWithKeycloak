package com.example.webserviceWithKeycloak.Controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/publicAccess")
public class PublicController {
	
	@GetMapping
	public String getPublicMessage(Principal principal) {
		return "You have public access, just like everyone else";
	}
}
