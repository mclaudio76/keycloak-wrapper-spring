package mclaudio76.identityaccessmanager.springconfig;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.extern.java.Log;
import mclaudio76.identityaccessmanager.IdentityAuthenticationManagerClient;
import mclaudio76.identityaccessmanager.keycloack.KeyCloackClient;

@Configuration
@EnableConfigurationProperties(ConfigIAM.class)
@Log
public class IdentityAuthenticationConfiguration {
	
	private final String KEYCLOAK = "keycloak";
	
	@Bean
	IdentityAuthenticationManagerClient identiyAuthenticationManagerClient(ConfigIAM properties) {
		if(properties.getProvider().trim().equalsIgnoreCase(KEYCLOAK)) {
	 		return new KeyCloackClient(properties.getServer(), 
					properties.getPort(), 
					properties.getAdminuser(), 
					properties.getAdminpassword(),
					properties.getClientid(), 
					properties.getClientsecret());
		}
		log.severe("Unable to instantiante IdentityAuthentication manager for provider ["+properties.getProvider()+"]");
		return null;
	}
	
	
}
