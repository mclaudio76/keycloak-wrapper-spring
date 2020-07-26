package mclaudio76.identityaccessmanager.keycloack;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import mclaudio76.identityaccessmanager.AuthenticatedUser;
import mclaudio76.identityaccessmanager.IdentityAuthenticationManagerClient;
import mclaudio76.identityaccessmanager.IdentityAuthenticationException;
import mclaudio76.identityaccessmanager.Role;
import mclaudio76.identityaccessmanager.keycloack.AuthorizationResponse.RoleList;

public class KeyCloackClient implements IdentityAuthenticationManagerClient {
	
	private RestTemplate restTemplate;
	private String clientSecret 			= "";
	private String clientID			    	= "";
	private String server		    		= "";
	private String port				    	= "";
	private String adminMasterPassword		= "";
	private String adminMaster				= "";
	private final String REALM_ACCESS	    = "realm_access";
	private String realm					= "";
	
	
	public KeyCloackClient(String server, String port, String adminUser, String adminPassword, String clientID, String clientSecret) {
		RestTemplateBuilder builder = new RestTemplateBuilder();
		restTemplate 	 			= builder.build();
		this.port     	  		    = port;
		this.server   	  		    = server;
		this.adminMaster  		    = adminUser;
		this.adminMasterPassword    = adminPassword;
		this.clientID			    = clientID;
		this.clientSecret		    = clientSecret;
	}
	
	@Override
	public IdentityAuthenticationManagerClient setRealm(String realm) {
		this.realm = realm;
		return this;
	}
	
	
	@Override
	public AuthenticatedUser login(String userID, String password) throws IdentityAuthenticationException {
		AuthorizationResponse authentication = authenticateUser(clientID, realm, userID, password);
		RealmUser realmUser					 = findUser(userID);
		List<Role> roles					 = getUserRoles(userID);
		return new AuthenticatedUser().setUserData(realmUser).setAuthorizationData(authentication).setRoles(roles);
	}
	
	@Override
	public void addRoleToUser(String username, String role) throws IdentityAuthenticationException{
		handleRolesForUser(username, role, HttpMethod.POST);
	}
	
	@Override
	public void removeRoleFromUser(String username, String role) throws IdentityAuthenticationException {
		handleRolesForUser(username, role, HttpMethod.DELETE);
	}
	
	@Override
	public boolean changeUserPassword(String username, String newPassword) throws IdentityAuthenticationException {
		RealmUser user = findUser(username);
		AuthorizationResponse adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
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
	
	
	private AuthorizationResponse authenticateUser(String clientID, String realm, String userID, String password) throws IdentityAuthenticationException {
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
			ResponseEntity<AuthorizationResponse> response =   restTemplate.exchange(url, 
																HttpMethod.POST,
																entity,
																AuthorizationResponse.class);
			
			
			AuthorizationResponse auth = response.getBody();
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
		catch(RestClientException e) {
			throw new IdentityAuthenticationException("User ["+userID+"] can't be authenticated.");
		}
		catch(Exception e) {
			throw new IdentityAuthenticationException("[INTERNAL-ERROR]"+ e.getMessage());
		}
	}

	private AuthorizationResponse authenticateKeyCloackAdminUser(String userID, String password) throws IdentityAuthenticationException {
		return authenticateUser("admin-cli", "master", userID, password);
	}
	
	private RealmUser[] listUsersForRealm() throws IdentityAuthenticationException {
		AuthorizationResponse adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
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
		catch(HttpClientErrorException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	private RealmUser findUser(String username) throws IdentityAuthenticationException {
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
	
	
	
	
	private List<Role> getUserRoles(String username)  throws IdentityAuthenticationException {
		RealmUser user = findUser(username);
		AuthorizationResponse adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
		String authToken		= adminAuth.getAccessToken();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer "+authToken);
		headers.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> entity = new HttpEntity<String>("", headers);
		String url = "http://"+server+":"+port+"/auth/admin/realms/"+realm+"/users/"+user.id+"/role-mappings/realm/composite";
		try {
			List<Role> assignedRoles = new ArrayList<>();
			ResponseEntity<RoleEntity[]> response =   restTemplate.exchange(url, 
																HttpMethod.GET,
																entity,
																RoleEntity[].class);
			for(RoleEntity r :  response.getBody()) {
				assignedRoles.add(new Role(r.name, r.description));
			}
			return assignedRoles;
		}
		catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	
	
	private RoleEntity[] getAvailableRoles(String username) throws IdentityAuthenticationException {
		RealmUser user = findUser(username);
		AuthorizationResponse adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
		String authToken		= adminAuth.getAccessToken();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer "+authToken);
		headers.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> entity = new HttpEntity<String>("", headers);
		String url = "http://"+server+":"+port+"/auth/admin/realms/"+realm+"/users/"+user.id+"/role-mappings/realm/available";
		ResponseEntity<RoleEntity[]> response =   restTemplate.exchange(url, HttpMethod.GET,entity,	RoleEntity[].class);
		return response.getBody();
	}
	
	
	
	private void handleRolesForUser(String username, String role, HttpMethod verb) throws IdentityAuthenticationException {
		RealmUser user 			= findUser(username);
		RoleEntity[] assignableRoles 	= getAvailableRoles(username);
		RoleEntity   requestRole		= null;
		for(RoleEntity x : assignableRoles) {
			if(x.name.trim().equalsIgnoreCase(role)) {
				requestRole = x;
			}
		}
		if(requestRole != null) {
			RoleEntity[] rolesToChange    = new RoleEntity[1];
			rolesToChange[0]		= requestRole;
			AuthorizationResponse adminAuth = authenticateKeyCloackAdminUser(adminMaster, adminMasterPassword);
			String authToken		= adminAuth.getAccessToken();
			HttpHeaders headers = new HttpHeaders();
			headers.add("Authorization", "Bearer "+authToken);
			headers.setContentType(MediaType.APPLICATION_JSON);
			HttpEntity<RoleEntity[]> entity = new HttpEntity<RoleEntity[]>(rolesToChange, headers);
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
		else {
			throw new IdentityAuthenticationException("Role ["+role+"] can't be assigned to ["+username+"]");
		}
	}
	
	

	
}
