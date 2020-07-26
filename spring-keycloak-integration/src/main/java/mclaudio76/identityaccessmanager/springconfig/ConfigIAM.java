package mclaudio76.identityaccessmanager.springconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@ConfigurationProperties(prefix = "lisaerp.iam")
@Getter @Setter
public class ConfigIAM {
	private String server;
	private String port;
	private String adminuser;
	private String adminpassword;
	private String clientid;
	private String clientsecret;
	private String provider; // Should be KeyCloak.
}
