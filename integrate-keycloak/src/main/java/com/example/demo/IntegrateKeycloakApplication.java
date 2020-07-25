package com.example.demo;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.security.jwt.JwtHelper;

@SpringBootApplication
public class IntegrateKeycloakApplication {

	public static void main(String[] args) {
		//authenticate(args);
		validateToken(args);
	}
	
	
	public static void authenticate(String[] args) {
		//SpringApplication.run(IntegrateKeycloakApplication.class, args);
		
		String clientSecret = "a64fd271-b77e-46ed-951d-7b7043596376";
		String realmName	= "spring-realm";
		String appName	    = "spring-app";
		
		String username	    = "utente";
		String password	    = "utente";
		
		Keycloak keycloak = KeycloakBuilder.builder()
			    .serverUrl("http://localhost:9080/auth")
			    .grantType(OAuth2Constants.PASSWORD)
			    .realm(realmName)
			    .clientId(appName)
			    	
				 .username(username)
			    .password(password)
			    .clientSecret(clientSecret)
			    .resteasyClient(
			        new ResteasyClientBuilder()
			            .connectionPoolSize(10).build()
			    ).build();
		
		AccessTokenResponse token = keycloak.tokenManager().getAccessToken();
		String tkString = token.getToken();
		String claims 	= JwtHelper.decode(tkString).getClaims();
		
		System.out.println("Token   --> "+token.getToken());
		System.out.println("Refresh --> "+token.getRefreshToken());
		System.out.println("Claims  --> "+claims);
		
	}
	
	
	
	public static void validateToken(String[] args) {
		//SpringApplication.run(IntegrateKeycloakApplication.class, args);
		String tokenString	= "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJPVlMtaF82eVVFOHdOYUFMV3VWemliU3NGRnRsY1dnRW9OOUFsNXVmUTVFIn0.eyJleHAiOjE1OTUwNDk1ODEsImlhdCI6MTU5NTA0OTI4MSwianRpIjoiOTQwZDQ5ZWMtN2NjMi00YjhjLWFmMDUtNDhhYTJhYTYzMTE1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDgwL2F1dGgvcmVhbG1zL3NwcmluZy1yZWFsbSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyZTFiYTE3Mi00N2EyLTQ0ZGEtYWZhZS1hYmVkMjgwMmU5NzgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJzcHJpbmctYXBwIiwic2Vzc2lvbl9zdGF0ZSI6Ijc2YzZhYTk0LTAzNGMtNDBhZi1hMjI0LWJiN2Q3OGMyZGVmNSIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiUk9MRV9VU0VSIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVXRlbnRlIGJhc2UiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1dGVudGUiLCJnaXZlbl9uYW1lIjoiVXRlbnRlIGJhc2UifQ.Q8XcdAba1xQmyAjT69guD9vTHAr3a7sc4rswWYHp11gu9pb83OV4mbdLZf0Bsqgf6TWyrqCe0hRsgpdNMeCiD9cTs-ZcfzZE1KFztW9qc3FdXUb3GsQfwkIRnvfLZpfoXVWGeBQWsvYO0YO3wNqHKeBjMRUygw90wcrD69Rcw2nBMRslSMNM1kNd61IPvbSvtL90RBeBFNGOanP94TelwKaiH0wVny6WFoDlW6e-eOVA3fu3xNU1T-YJv_sG9rOKyQ4Lq56pixp306C2LkTNJY0PHOoXkxOHajmUQIKLr_KmYlodh0muVAL0HGsoEozO2duxgqFkl-YCFdkrPCwOog";
		String clientSecret = "a64fd271-b77e-46ed-951d-7b7043596376";
		String realmName	= "spring-realm";
		String appName	    = "spring-app";
		Keycloak keycloak = KeycloakBuilder.builder()
			    .serverUrl("http://localhost:9080/auth")
			    .realm(realmName)
			    .clientId(appName)
			    .clientSecret(clientSecret)
			    .resteasyClient(
			        new ResteasyClientBuilder()
			            .connectionPoolSize(10).build()
			    ).build();
		keycloak.tokenManager().invalidate(tokenString);
		
	}
	
	
	

}
