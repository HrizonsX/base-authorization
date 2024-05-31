package io.github.opensabre.authorization.oauth2;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * spring-security-oauth2-authorization-server 不支持 password 模式的 oauth2 认证，所以需要自己手工编写代码添加支持
 **/
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final Set<String> scopes;

    /**
     * @param clientPrincipal      the authenticated client principal
     * @param additionalParameters the additional parameters 比 client_credentials 多出来的 username 和 password 参数在这里
     */
    public OAuth2PasswordAuthenticationToken(Authentication clientPrincipal,
                                             @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {

        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

    /**
     * Returns the requested scope(s).
     *
     * @return the requested scope(s), or an empty {@code Set} if not available
     */
    public Set<String> getScopes() {
        return this.scopes;
    }
}
