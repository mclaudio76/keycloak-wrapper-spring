package mclaudio76.keycloack;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import mclaudio76.keycloack.Authorization.RoleList;

public class KeyCloackClient {
	
	private RestTemplate restTemplate;
	private String clientSecret 			= "";
	private String clientID			    	= "";
	private String server		    		= "";
	private String port				    	= "";
	private String adminMasterPassword		= "";
	private String adminMaster				= "";
	private final String REALM_ACCESS	    = "realm_access";
	private String realm					= "";
	
	
	public KeyCloackClient(String server, String port, String adminUser, String adminPassword) {
		RestTemplateBuilder builder = new RestTemplateBuilder();
		restTemplate 	 			= builder.build();
		this.port     	  		    = port;
		this.server   	  		    = server;
		this.adminMaster  		    = adminUser;
		this.adminMasterPassword    = adminPassword;
	}
	
	public KeyCloackClient setRealm(String realm) {
		this.realm = realm;
		return this;
	}
	
	
	public KeyCloackClient setClientID(String clientID) {
		this.clientID = clientID;
		return this;
	}
	
	public KeyCloackClient setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
		return this;
	}
	
	
	
	public Authorization authenticateKeyCloackAdminUser(String userID, String password) {
		return authenticateUser("admin-cli", "master", userID, password);
	}
	
	
	public Authorization authenticateUser(String userID, String password) {
		return authenticateUser(clientID, realm, userID, password);
	}
	
	
	private Authorization authenticateUser(String clientID, String realm, String userID, String password) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("client_id",       clientID);
		map.add("grant_type",      "password");
		map.add("client_secret",   clientSecret);
		map.add("scope", 		   "openid");
		map.add("username", 	   userID);
		map.add("password", 	   password);
		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
		String url = "http://"+server+":"+port+"/auth/realms/"+realm+"/protocol/openid-connect/token";
		try {
			ResponseEntity<Authorization> response =   restTemplate.exchange(url, 
																HttpMethod.POST,
																entity,
																Authorization.class);
			Authorization auth = response.getBody();
			JWTClaimsSet claims = JWTParser.parse(auth.getAccessToken()).getJWTClaimsSet();
			for(String key : claims.getClaims().keySet()) {
				Object claim = claims.getClaim(key);
				auth.addClaim(key,claim);
				if(key.trim().equalsIgnoreCase(REALM_ACCESS)) {
					RoleList roleList = new ObjectMapper().readValue(claim.toString(), RoleList.class); 
					auth.setRoleList(roleList);
				}
			}
			return auth;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public RealmUser[] listUsersForRealm() {
		Authorization adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
		String authToken		= adminAuth.getAccessToken();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer "+authToken);
		headers.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> entity = new HttpEntity<String>("", headers);
		String url = "http://"+server+":"+port+"/auth/admin/realms/"+realm+"/users";
		try {
			ResponseEntity<RealmUser[]> response =   restTemplate.exchange(url, 
																HttpMethod.GET,
																entity,
																RealmUser[].class);
			RealmUser[] users = response.getBody();
			return users;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public RealmUser findUser(String username) {
		RealmUser[] users = listUsersForRealm();
		if(users != null) {
			for(RealmUser user : users) {
				if(user.username.trim().equalsIgnoreCase(username)) {
					return user;
				}
			}
		}
		return null;
	}
	
	public boolean changePassword(String username, String newPassword) {
		RealmUser user = findUser(username);
		Authorization adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
		String authToken		= adminAuth.getAccessToken();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer "+authToken);
		headers.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<ChangePasswordRequest> entity = new HttpEntity<ChangePasswordRequest>(new ChangePasswordRequest(newPassword, false), headers);
		String url = "http://"+server+":"+port+"/auth/admin/realms/"+realm+"/users/"+user.id+"/reset-password";
		try {
			ResponseEntity<String> response =   restTemplate.exchange(url, 
																HttpMethod.PUT,
																entity,
																String.class);
			return response.getStatusCode().is2xxSuccessful();
		}
		catch(Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	
	public Role[] rolesAssignedToUser(String username)  {
		RealmUser user = findUser(username);
		Authorization adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
		String authToken		= adminAuth.getAccessToken();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer "+authToken);
		headers.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> entity = new HttpEntity<String>("", headers);
		String url = "http://"+server+":"+port+"/auth/admin/realms/"+realm+"/users/"+user.id+"/role-mappings/realm/composite";
		try {
			ResponseEntity<Role[]> response =   restTemplate.exchange(url, 
																HttpMethod.GET,
																entity,
																Role[].class);
			Role[] assignedRoles = response.getBody();
			for(Role r : assignedRoles) {
				System.out.println(r.id +" "+r.name+" "+r.description);
			}
			return assignedRoles;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public Role[] rolesAssignableToUser(String username)  {
		RealmUser user = findUser(username);
		Authorization adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
		String authToken		= adminAuth.getAccessToken();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer "+authToken);
		headers.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> entity = new HttpEntity<String>("", headers);
		String url = "http://"+server+":"+port+"/auth/admin/realms/"+realm+"/users/"+user.id+"/role-mappings/realm/available";
		try {
			ResponseEntity<Role[]> response =   restTemplate.exchange(url, 
																HttpMethod.GET,
																entity,
																Role[].class);
			Role[] assignedRoles = response.getBody();
			for(Role r : assignedRoles) {
				System.out.println(r.id +" "+r.name+" "+r.description);
			}
			return assignedRoles;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public void addRoleToUser(String username, String role) {
		handleRolesForUser(username, role, HttpMethod.POST);
	}
	
	public void removeRoleFromUser(String username, String role) {
		handleRolesForUser(username, role, HttpMethod.DELETE);
	}
	
	public void handleRolesForUser(String username, String role, HttpMethod verb) {
		RealmUser user 			= findUser(username);
		Role[] assignableRoles 	= rolesAssignableToUser(username);
		Role   requestRole		= null;
		for(Role x : assignableRoles) {
			if(x.name.trim().equalsIgnoreCase(role)) {
				requestRole = x;
			}
		}
		if(requestRole != null) {
			Role[] rolesToChange    = new Role[1];
			rolesToChange[0]		= requestRole;
			Authorization adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
			String authToken		= adminAuth.getAccessToken();
			HttpHeaders headers = new HttpHeaders();
			headers.add("Authorization", "Bearer "+authToken);
			headers.setContentType(MediaType.APPLICATION_JSON);
			HttpEntity<Role[]> entity = new HttpEntity<Role[]>(rolesToChange, headers);
			String url = "http://"+server+":"+port+"/auth/admin/realms/"+realm+"/users/"+user.id+"/role-mappings/realm";
			try {
				ResponseEntity<String> response =   restTemplate.exchange(url, 
																	verb,
																	entity,
																	String.class);
				
			}
			catch(Exception e) {
				e.printStackTrace();
				
			}
		}
	}
	
	

	
}
