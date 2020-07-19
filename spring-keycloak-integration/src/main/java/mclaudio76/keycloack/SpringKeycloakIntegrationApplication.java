package mclaudio76.keycloack;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringKeycloakIntegrationApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringKeycloakIntegrationApplication.class, args);
	}
	
	@Bean
	CommandLineRunner execute() {
		return new CommandLineRunner() {
			@Override
			public void run(String... args) throws Exception {
				KeyCloackClient client = new KeyCloackClient("localhost", "9080", "admin", "adminpassword")
							.setClientID("spring-app")
							.setClientSecret("1bd6d6df-c789-4ba6-988d-87592b3e1f59")
							.setRealm("spring-realm");

				//client.authenticateUser("spring-realm", "utente", "utente");
				//RealmUser[] users = client.listUsersForRealm("spring-realm");
				//client.changePassword("spring-realm", "mimmo", "beltest");
				//client.authenticateUser("spring-realm", "mimmo", "beltest");
				//client.listRolesForUser("spring-realm", "mimmo");
				//client.assignableRoles("spring-realm", "mimmo");
				//client.removeRoleFromUser("spring-realm","mimmo", "ROLE_AUDITOR");
				client.addRoleToUser("mimmo", "ROLE_AUDITOR");
				
				System.exit(1);
			}
		};
	}
	

}
