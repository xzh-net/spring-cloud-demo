package net.xzh.oauth.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import net.xzh.oauth.service.MyUserDetailsService;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private DataSource dataSource;

	@Autowired
	private MyUserDetailsService userDetailsService;
	
	@Autowired
	private AuthenticationManager authenticationManager;

	/**
	 * 配置客户端详情
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.withClientDetails(jdbcClientDetailsService());
	}

	/**
	 * 配置令牌访问端点和令牌服务
	 */
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		// JwtToken存储,核心：必须配置 authenticationManager 和 userDetailsService
		endpoints.authenticationManager(authenticationManager).userDetailsService(userDetailsService)
				.tokenStore(jwtTokenStore()).accessTokenConverter(jwtAccessTokenConverter());
		
//		//存储到数据库中
//		endpoints.tokenStore(tokenStore())
//				.userDetailsService(userDetailsService)// 读取验证用户信息
//        		.pathMapping("/oauth/confirm_access", "/custom/confirm_access")// 自定义授权跳转
//				.authenticationManager(authenticationManager);// 注入WebSecurityConfig配置的bean
	}
	/**
	 * 配置令牌端点的安全约束
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		// 对获取Token的请求不再拦截
		oauthServer.tokenKeyAccess("permitAll()")
				// 验证获取Token的验证信息
				.checkTokenAccess("isAuthenticated()")
				// 这个如果配置支持allowFormAuthenticationForClients的，且对/oauth/token请求的参数中有client_id和client-secret的会走ClientCredentialsTokenEndpointFilter来保护
				// 如果没有支持allowFormAuthenticationForClients或者有支持但对/oauth/token请求的参数中没有client_id和client_secret的，走basic认证保护
				.allowFormAuthenticationForClients();
	}

	@Bean
    public JwtTokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }
	
	@Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey("123");   //  Sets the JWT signing key
        return jwtAccessTokenConverter;
    }
	
	@Bean
	public TokenStore tokenStore() {
		// token存储
		return new JdbcTokenStore(dataSource);
	}

	@Bean
	public ClientDetailsService jdbcClientDetailsService() {
		// 存储client信息
		return new JdbcClientDetailsService(dataSource);
	}
}
