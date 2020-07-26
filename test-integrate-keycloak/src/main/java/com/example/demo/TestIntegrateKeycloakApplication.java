package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;

import mclaudio76.identityaccessmanager.IdentityAuthenticationException;
import mclaudio76.identityaccessmanager.IdentityAuthenticationManagerClient;

@SpringBootApplication
public class TestIntegrateKeycloakApplication {

	public static void main(String[] args) {
		SpringApplication.run(TestIntegrateKeycloakApplication.class, args);
	}

	@Autowired
	IdentityAuthenticationManagerClient client;
	
	
	@Bean
	CommandLineRunner execute() {
		return new CommandLineRunner() {
			@Override
			public void run(String... args) throws Exception {
				try {
					//IdentityAuthenticationManagerClient client = new KeyCloackClient("localhost", "9080", "admin", 
					//		"adminpassword","spring-app","1bd6d6df-c789-4ba6-988d-87592b3e1f59");
					
	
					//client.authenticateUser("spring-realm", "utente", "utente");
					///RealmUser[] users = client.listUsersForRealm();
					//client.changePassword("spring-realm", "mimmo", "beltest");
					UserDetails user = client.login("spring-realm", "mimmo", "claudio");
					client.changeUserPassword("spring-realm", "mimmo", "beltest");
					//client.listRolesForUser("spring-realm", "mimmo");
					//client.assignableRoles("spring-realm", "mimmo");
					//client.removeRoleFromUser("spring-realm","mimmo", "ROLE_AUDITOR");
					//client.addRoleToUser("mimmo", "ROLE_AUDITOR");
				}
				catch(IdentityAuthenticationException authException) {
					
				}
				
				System.exit(1);
			}
		};
	}
}
