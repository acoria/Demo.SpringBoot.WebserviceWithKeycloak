package com.example.webserviceWithKeycloak.Controller;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/privateAccess")
public class PrivateController {
	
	@PreAuthorize("hasRole('USER')")
	@GetMapping
	public String getPrivateMessage(Principal principal) {
		return "Congraz! You have private access";
	}
	
}