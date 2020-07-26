package mclaudio76.identityaccessmanager.keycloack;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RealmUser implements Serializable {
	
	@JsonIgnoreProperties(ignoreUnknown = true)
	public static class RealmUserAccess {
		 public boolean manageGroupMembership;
		 public boolean view;
		 public boolean mapRoles;
		 public boolean manage;
		 public boolean impersonate;
	}
	
	public String  id;
	public long    createdTimestamp;
	public String  username;
	public boolean enabled;
	public boolean totp;
	public boolean emailVerified;
	public String  firstName;
	public long notBefore;
	public String  realm;
	//disableableCredentialTypes ??
	//requiredActions;
	
	public RealmUserAccess access;
	
	
	
}
