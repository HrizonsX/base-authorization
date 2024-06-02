package io.github.opensabre.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.opensabre.authorization.entity.Role;
import io.github.opensabre.authorization.entity.User;
import io.github.opensabre.authorization.oauth2.OAuth2AuthenticationUtils;
import io.github.opensabre.authorization.oauth2.OAuth2PasswordAuthenticationConverter;
import io.github.opensabre.authorization.oauth2.OAuth2PasswordAuthenticationProvider;
import io.github.opensabre.authorization.oauth2.Oauth2RegisteredClientRepository;
import io.github.opensabre.authorization.service.IRoleService;
import io.github.opensabre.authorization.service.IUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.annotation.Resource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Slf4j
@Configuration
public class AuthorizationServerConfig {

    @Resource
    private JdbcTemplate jdbcTemplate;

    @Resource
    private Oauth2RegisteredClientRepository oauth2RegisteredClientRepository;

    @Resource
    private UserDetailsService userDetailsService;

    @Resource
    private IRoleService roleService;

    @Resource
    private IUserService userService;

    /**
     * 用于密码加密
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 用于jwt解码
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 用于jwt编码
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(jwkSource());
    }

    /**
     * token生成
     *
     */
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder());
        jwtGenerator.setJwtCustomizer(jwtCustomizer());
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * 自定义JWT token内容
     *
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            JwsHeader.Builder headers = context.getHeaders();
            headers.header("source", "oauth2");
            JwtClaimsSet.Builder claims = context.getClaims();
            Map<String, Object> map = claims.build().getClaims();
            String uniqueId = (String) map.get(JwtClaimNames.SUB);
            User user = userService.getByUniqueId(uniqueId);
            if (Objects.nonNull(user)) {
                Set<Role> result = roleService.queryUserRolesByUserId(user.getId());
                claims.claim("roles", result);
            }
            log.info("context:{}", context);
        };
    }

    /**
     * 端点的 Spring Security 过滤器链
     *
     * @param httpSecurity
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        log.info("Init HttpSecurity for Oauth2");
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        httpSecurity.requestMatcher(endpointsMatcher).authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);
        // 加入的额外配置逻辑 支持密码模式
        httpSecurity.apply(
                authorizationServerConfigurer.tokenEndpoint(
                        oAuth2TokenEndpointConfigurer -> oAuth2TokenEndpointConfigurer.accessTokenRequestConverter(
                                new DelegatingAuthenticationConverter(Arrays.asList(
                                        new OAuth2ClientCredentialsAuthenticationConverter(),
                                        // 加入密码模式转换器
                                        new OAuth2PasswordAuthenticationConverter(),
                                        new OAuth2AuthorizationCodeAuthenticationConverter(),
                                        new OAuth2RefreshTokenAuthenticationConverter())
                                )
                        )
                )
        );

        //注入新的AuthenticationManager
        httpSecurity.authenticationManager(authenticationManager(httpSecurity));
        addOAuth2PasswordAuthenticationProvider(httpSecurity);
        // 表单登录处理 从授权服务器过滤器链
        httpSecurity.formLogin(Customizer.withDefaults());
        // 未通过身份验证异常时重定向到登录页面授权端点
        httpSecurity.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        return httpSecurity.build();
    }

    /**
     * 操作oauth2_authorization表，token等相关信息表
     *
     * @return OAuth2AuthorizationService
     */
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, oauth2RegisteredClientRepository);
    }

    /**
     * 授权确认信息处理服务，操作oauth2_authorization_consent表，权限相关表。
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, oauth2RegisteredClientRepository);
    }

    /**
     * 生成jwk资源,com.nimbusds.jose.jwk.source.JWKSource用于签署访问令牌的实例。
     *
     * @return JWKSource<SecurityContext>
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成密钥对,启动时生成的带有密钥的实例java.security.KeyPair用于创建JWKSource上述内容
     *
     * @return KeyPair
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * ProviderSettings配置 Spring Authorization Server的实例
     *
     * @return ProviderSettings
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().build();
    }


    /**
     * 构造一个AuthenticationManager
     * 使用自定义的userDetailsService和passwordEncoder
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder())
                .and()
                .build();
        return authenticationManager;
    }

    /**
     * 下面大段代码逻辑也是从 spring 官方源码复制改动而来
     * 比如 OAuth2TokenEndpointConfigurer#createDefaultAuthenticationProviders 方法中处理逻辑
     */
    private void addOAuth2PasswordAuthenticationProvider(HttpSecurity http) throws Exception {

        AuthenticationManager authenticationManager = authenticationManager(http);
        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
        if (authorizationService == null) {
            authorizationService = OAuth2AuthenticationUtils.getOptionalBean(http, OAuth2AuthorizationService.class);
            if (authorizationService == null) {
                authorizationService = new InMemoryOAuth2AuthorizationService();
            }
            http.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        }

        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
        if (tokenGenerator == null) {
            tokenGenerator = OAuth2AuthenticationUtils.getOptionalBean(http, OAuth2TokenGenerator.class);
            if (tokenGenerator == null) {
                JwtGenerator jwtGenerator = OAuth2AuthenticationUtils.getJwtGenerator(http);
                OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
                OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer = OAuth2AuthenticationUtils.getAccessTokenCustomizer(http);
                if (accessTokenCustomizer != null) {
                    accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
                }
                OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
                if (jwtGenerator != null) {
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(
                            jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
                } else {
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(
                            accessTokenGenerator, refreshTokenGenerator);
                }
            }
            http.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
        }
        OAuth2PasswordAuthenticationProvider passwordAuthenticationProvider =
                new OAuth2PasswordAuthenticationProvider(authenticationManager, authorizationService, tokenGenerator);

        // 额外补充添加一个认证provider
        http.authenticationProvider(passwordAuthenticationProvider);
    }
}
