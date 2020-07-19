package mclaudio76.keycloack;

public class ChangePasswordRequest {
	public boolean temporary      = false;
	public final String    type   = "password";
	public String    value  	  = "";
	
	public ChangePasswordRequest(String newPassword, Boolean isTemporary) {
		this.value 		= newPassword;
		this.temporary  = isTemporary;
	}
	
}
