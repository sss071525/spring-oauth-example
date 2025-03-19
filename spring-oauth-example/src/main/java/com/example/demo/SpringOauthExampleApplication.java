package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SpringOauthExampleApplication {

	public static void main(String[] args) {
		 BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
	        String encodedPassword = encoder.encode("angular-secret");
	        System.out.println("Encoded Password for angular-secret: " + encodedPassword);
		SpringApplication.run(SpringOauthExampleApplication.class, args);
	}

}
