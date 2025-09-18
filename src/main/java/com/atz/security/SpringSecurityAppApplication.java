package com.atz.security;

import com.atz.security.entities.UserEntity;
import com.atz.security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecurityAppApplication {

	public static void main(String[] args) {

		SpringApplication.run(SpringSecurityAppApplication.class, args);
	}
}
