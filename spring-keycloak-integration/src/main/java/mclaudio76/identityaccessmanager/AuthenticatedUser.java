package mclaudio76.identityaccessmanager;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import mclaudio76.identityaccessmanager.keycloack.AuthorizationResponse;
import mclaudio76.identityaccessmanager.keycloack.RealmUser;

public class AuthenticatedUser implements UserDetails {

	private static final long serialVersionUID = 1L;
	
	private List<Role> roles;
	private UserInfo   userInfo;
	
	private String access_token;
	private String refresh_token;
	private String id_token;
	private String token_type;
	private String session_state;
	private String scope;
	private long   expires_in;
	private long   refresh_expires_in;

	
    public AuthenticatedUser setAuthorizationData(AuthorizationResponse auth) {
    	this.access_token = auth.getAccessToken();
    	this.refresh_token = auth.getRefreshToken();
    	this.id_token	   = auth.getIdToken();
    	this.token_type	   = auth.getTokenType();
    	this.session_state = auth.getSessionState();
    	this.scope		   = auth.getScope();
    	this.expires_in    = auth.getExpiresIn();
    	return this;
    }
    
    public AuthenticatedUser setUserData(RealmUser user) {
    	userInfo 			  = new UserInfo();
    	userInfo.createdTimestamp = user.createdTimestamp;
    	userInfo.username		  = user.username;
    	userInfo.enabled		  = user.enabled;
    	userInfo.emailVerified	  = user.emailVerified;
    	userInfo.realName		  = user.firstName;
    	return this;
    }
    
    public AuthenticatedUser setRoles(List<Role> list) {
		this.roles = list;
		return this;
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return roles;
	}
	
	@Override
	public String getPassword() {
		return null;
	}
	
	@Override
	public String getUsername() {
		return userInfo.username;
	}
	
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	
	@Override
	public boolean isEnabled() {
	    return userInfo.enabled;
	}
	
	public String getAccessToken() {
		return access_token;
	}

	
	public String getRefreshToken() {
		return refresh_token;
	}

	

	

	
	
}
