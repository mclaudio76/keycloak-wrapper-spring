package mclaudio76.identityaccessmanager;

import java.io.Serializable;

public class UserInfo implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	public long    createdTimestamp;
	public String  username;
	public boolean enabled;
	public boolean emailVerified;
	public String  realName;
	
}
