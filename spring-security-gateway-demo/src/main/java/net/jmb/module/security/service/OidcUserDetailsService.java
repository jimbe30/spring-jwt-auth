package net.jmb.module.security.service;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import net.jmb.module.security.model.OidcUserDetails;

@Service
public class OidcUserDetailsService implements UserDetailsManager {
	
		protected final Log logger = LogFactory.getLog(getClass());
		protected final Map<String, OidcUserDetails> users = new HashMap<>();
		private AuthenticationManager authenticationManager;
		
		public void createUser(UserDetails user) {
			Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
			Assert.isTrue(user.getClass().isAssignableFrom(OidcUserDetails.class) , "user should be instance of OidcUserDetails");
			users.put(user.getUsername().toLowerCase(), (OidcUserDetails) user);
		}

		public void deleteUser(String username) {
			users.remove(username.toLowerCase());
		}

		public void updateUser(UserDetails user) {
			Assert.isTrue(userExists(user.getUsername()), "user should exist");
			Assert.isTrue(user.getClass().isAssignableFrom(OidcUserDetails.class) , "user should be instance of OidcUserDetails");
			users.put(user.getUsername().toLowerCase(), (OidcUserDetails) user);
		}

		public boolean userExists(String username) {
			return users.containsKey(username.toLowerCase());
		}

		public void changePassword(String oldPassword, String newPassword) {
			
			Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
			if (currentUser == null) {
				throw new AccessDeniedException(
					"Can't change password as no Authentication object found in context for current user.");
			}			
			String username = currentUser.getName();
			logger.debug("Changing password for user '" + username + "'");
			// If an authentication manager has been set, re-authenticate the user with the supplied password.
			if (authenticationManager != null) {
				logger.debug("Reauthenticating user '" + username + "' for password change request.");
				authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
			} else {
				logger.debug("No authentication manager set. Password won't be re-checked.");
			}
			OidcUserDetails user = users.get(username);
			if (user == null) {
				throw new IllegalStateException("Current user doesn't exist in database.");
			}
			user.setPassword(newPassword);
		}

		public OidcUserDetails updatePassword(OidcUserDetails user, String newPassword) {
			String username = user.getUsername();
			OidcUserDetails mutableUser = this.users.get(username.toLowerCase());
			mutableUser.setPassword(newPassword);
			return mutableUser;
		}

		public OidcUserDetails loadUserByUsername(String username)	throws UsernameNotFoundException {
			
			OidcUserDetails user = users.get(username.toLowerCase());
			if (user == null) {
				
				throw new UsernameNotFoundException(username);
			}
			return user;
		}

		public void setAuthenticationManager(AuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
		}


}
