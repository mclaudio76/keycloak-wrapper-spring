package mclaudio76.identityaccessmanager.springconfig;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;

import mclaudio76.identityaccessmanager.IdentityAuthenticationManagerClient;
import mclaudio76.identityaccessmanager.keycloack.KeyCloackClient;

@Configuration
@EnableConfigurationProperties(ConfigIAM.class)
public class IdentityAuthenticationConfiguration {

	
	
	@Bean
	@Scope(scopeName = "prototype", proxyMode = ScopedProxyMode.TARGET_CLASS)
	IdentityAuthenticationManagerClient identiyAuthenticationManagerClient(ConfigIAM properties) {
		return new KeyCloackClient(properties.getServer(), 
				properties.getPort(), 
				properties.getAdminuser(), 
				properties.getAdminpassword(),
				properties.getClientid(), 
				properties.getClientsecret());
	}
	
	
}
