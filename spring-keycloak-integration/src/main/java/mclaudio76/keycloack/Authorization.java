package mclaudio76.keycloack;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Authorization implements Serializable {
	
private static final long serialVersionUID = 1L;
	
	static class RoleList {
		List<String> roles = new ArrayList<>();
		public void setRoles(List<String> roles) {
			this.roles = new ArrayList<>(roles);
		}
		
		public List<String> getRoles() {
			return this.roles;
		}
	}


	private String access_token;
	private String refresh_token;
	private String id_token;
	private String token_type;
	private String session_state;
	private String scope;
	private long   expires_in;
	private long   refresh_expires_in;
	
	private RoleList roleList = null;
		
	// Derived from claims
	private Map<String,Object> claims = new HashMap<>();
	
	
	
	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}

	public void setRefresh_token(String refresh_token) {
		this.refresh_token = refresh_token;
	}
	
	public void setId_token(String id_token) {
		this.id_token = id_token;
	}
	
	public void setToken_type(String token_type) {
		this.token_type = token_type;
	}
	
	public void setSession_state(String session_state) {
		this.session_state = session_state;
	}
	
	public void setScope(String scope) {
		this.scope = scope;
	}
	
	public void setExpires_in(long expires_in) {
		this.expires_in = expires_in;
	}
	public void setRefresh_expires_in(long refresh_expires_in) {
		this.refresh_expires_in = refresh_expires_in;
	}
	
	public String getAccessToken() {
		return access_token;
	}
	public String getRefreshToken() {
		return refresh_token;
	}
	public String getIdToken() {
		return id_token;
	}
	public String getTokenType() {
		return token_type;
	}
	public String getSessionState() {
		return session_state;
	}
	public String getScope() {
		return scope;
	}
	public long getExpiresIn() {
		return expires_in;
	}
	public long getRefreshExpiresIn() {
		return refresh_expires_in;
	}
	
	public void addClaim(String key, Object value) {
		this.claims.put(key, value);
	}
	
	public void setRoleList(RoleList rList) {
		this.roleList = rList;
	}
	
	public RoleList getRoleList() {
		return this.roleList;
	}
	    
}
