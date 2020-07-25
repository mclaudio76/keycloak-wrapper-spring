package mclaudio76.identityaccessmanager;

public interface IdentityAuthenticationManagerClient {

	IdentityAuthenticationManagerClient setRealm(String realm);
	AuthenticatedUser login(String username, String password) throws IdentityAuthenticationException;
	boolean changeUserPassword(String username, String newpassword) throws IdentityAuthenticationException;
	void addRoleToUser(String username, String rolename) throws IdentityAuthenticationException;
	void removeRoleFromUser(String username, String rolename) throws IdentityAuthenticationException;

}