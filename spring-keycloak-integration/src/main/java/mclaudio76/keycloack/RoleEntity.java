package mclaudio76.keycloack;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RoleEntity  implements Serializable {
	public String  id ="";
	public String  name ="";
	public String  description = "";
	public Boolean composite;
	public Boolean clientRole;
	public String  containerId = "";
}
