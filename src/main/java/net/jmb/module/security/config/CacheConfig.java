package net.jmb.module.security.config;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfig {	
	
	public static final String CACHE_SCOPE = "#root.caches[0].name";
	public static final String IDP_INFOS_CACHE = "idp_infos";
	
//	@Bean
//	public CacheManagerCustomizer<ConcurrentMapCacheManager> cacheManagerCustomizer() {
//	    return new CacheManagerCustomizer<ConcurrentMapCacheManager>() {
//	        @Override
//	        public void customize(ConcurrentMapCacheManager cacheManager) {
//	        	cacheManager.setCacheNames(Arrays.asList(IDP_INFOS_CACHE));
//	        }
//	    };
//	}

}
