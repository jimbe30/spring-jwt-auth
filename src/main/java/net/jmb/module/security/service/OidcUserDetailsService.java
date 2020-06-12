package net.jmb.module.security.service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import net.jmb.module.security.model.OidcUserDetails;

@Service
public class OidcUserDetailsService implements UserDetailsManager, Runnable {

	/**
	 * TODO mettre en place une infrastructure de log
	 */

	private Integer expirationSessionDelay;
	
	protected final Log logger = LogFactory.getLog(getClass());
	protected final Map<String, OidcUserDetails> users = new ConcurrentHashMap<>();
	
	@Autowired
	public OidcUserDetailsService(Integer expirationSessionDelay) {		
		this.expirationSessionDelay = expirationSessionDelay;
		if (expirationSessionDelay != null && expirationSessionDelay > 0) {
			new Thread(this).start();
		}
	}

	public void createUser(UserDetails user) {
		Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
		Assert.isTrue(user.getClass().isAssignableFrom(OidcUserDetails.class),
				"user should be instance of OidcUserDetails");
		OidcUserDetails oidcUser = (OidcUserDetails) user;
		oidcUser.setSessionExpirationDelay(expirationSessionDelay * 60 * 1000 );
		users.put(oidcUser.getUsername().toLowerCase(), oidcUser);
	}

	public void deleteUser(String username) {
		users.remove(username.toLowerCase());
	}

	public void updateUser(UserDetails user) {
		Assert.isTrue(userExists(user.getUsername()), "user should exist");
		Assert.isTrue(user.getClass().isAssignableFrom(OidcUserDetails.class),
				"user should be instance of OidcUserDetails");
		users.put(user.getUsername().toLowerCase(), (OidcUserDetails) user);
	}

	public boolean userExists(String username) {
		return users.containsKey(username.toLowerCase());
	}

	public OidcUserDetails updatePassword(OidcUserDetails user, String newPassword) {
		String username = user.getUsername();
		OidcUserDetails mutableUser = this.users.get(username.toLowerCase());
		mutableUser.setPassword(newPassword);
		return mutableUser;
	}

	public OidcUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		OidcUserDetails user = users.get(username.toLowerCase());
		if (user == null) {
			throw new UsernameNotFoundException(username);
		}
		user.updateLastAccessTime();
		return user;
	}
	
	private void removeExpiredUsers() {
		for (String name : users.keySet()) {
			if (!users.get(name).isCredentialsNonExpired()) {
				users.remove(name);
			}
		}
	}
	
	public void run() {
		while (true) {
			try {
				Thread.sleep(expirationSessionDelay * 60 * 1000);
			} catch (InterruptedException e) {
				new Thread(this).start();
			}
			removeExpiredUsers();
		}
	}	
	

	public void changePassword(String oldPassword, String newPassword) {}
	
	

}
