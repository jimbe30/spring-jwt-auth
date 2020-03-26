package net.jmb.module.security.service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import net.jmb.module.security.config.CacheConfig;
import net.jmb.oidc_demo.model.IdentityProviderRegistration;

@Service
@org.springframework.cache.annotation.CacheConfig(cacheNames = CacheConfig.IDP_INFOS_CACHE)
public class IdentityProviderService {
	
	@Autowired 	IdentityProviderService self;	
	@Autowired	private ModelMapper modelMapper;	
	@Autowired	private String securityBaseURL;
	
	@SuppressWarnings("unchecked")	
	@Cacheable(key = CacheConfig.CACHE_SCOPE)
	public Map<String, IdentityProviderRegistration> findIdentityProviders() throws IOException {
		
		Map<String, IdentityProviderRegistration> result = new HashMap<>();		
		RestTemplate restTemplate = new RestTemplate();		
		
		Map<String, ?> tmpResult = restTemplate.getForObject(securityBaseURL + "/login/discovery", Map.class);
		
		tmpResult.forEach( (providerId, data) -> {
			IdentityProviderRegistration registration = modelMapper.map(data, IdentityProviderRegistration.class);
			result.put(providerId, registration);
		});

		return result;
	}
	
	public IdentityProviderRegistration resolveIdentityProvider(OidcIdToken token) throws IOException {
		
		String issuer = token.getIssuer().toExternalForm();
		return self.findIdentityProviders()
				.values()
				.stream()
				.filter(idpRegistration -> idpRegistration.getIssuerURL().contains(issuer))
				.findFirst()
				.get();
	}

}
