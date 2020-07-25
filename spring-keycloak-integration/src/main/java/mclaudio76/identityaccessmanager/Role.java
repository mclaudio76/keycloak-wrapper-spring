package mclaudio76.identityaccessmanager;

import org.springframework.security.core.GrantedAuthority;

public class Role implements GrantedAuthority {
	
	public String  name 		= "";
	public String  description = "";
		
	public Role(String name, String description) {
		this.name = name;
		this.description = description;
	}

	@Override
	public String getAuthority() {
		return name;
	}
	
}
