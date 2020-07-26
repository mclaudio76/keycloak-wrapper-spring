package mclaudio76.identityaccessmanager;

public interface IdentityAuthenticationManagerClient {


	AuthenticatedUser login(String tenantID, String username, String password) throws IdentityAuthenticationException;
	boolean changeUserPassword(String tenantID, String username, String newpassword) throws IdentityAuthenticationException;
	void addRoleToUser(String tenantID, String username, String rolename) throws IdentityAuthenticationException;
	void removeRoleFromUser(String tenantID, String username, String rolename) throws IdentityAuthenticationException;

}