package io.github.opensabre.authorization.oauth2;

import io.github.opensabre.authorization.entity.Role;
import io.github.opensabre.authorization.entity.User;
import io.github.opensabre.authorization.service.IRoleService;
import io.github.opensabre.authorization.service.IUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Resource
    private IUserService userService;
    @Resource
    private IRoleService roleService;

    @Override
    public UserDetails loadUserByUsername(String uniqueId) {
        User user = userService.getByUniqueId(uniqueId);
        if (Objects.isNull(user)) {
            return null;
        }
        log.info("load oauth user. username: {}", user.getUsername());
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getEnabled(),
                user.getAccountNonExpired(),
                user.getCredentialsNonExpired(),
                user.getAccountNonLocked(),
                this.obtainGrantedAuthorities(user));
    }

    /**
     * 获得登录者所有角色的权限集合.
     *
     * @param user 用户信息
     * @return 权限集合
     */
    protected Set<GrantedAuthority> obtainGrantedAuthorities(User user) {
        if (Objects.isNull(user)) {
            return Collections.emptySet();
        }
        Set<Role> roles = roleService.queryUserRolesByUserId(user.getId());
        log.info("username: {}, roles: {}", user.getUsername(), roles);
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getCode())).collect(Collectors.toSet());
    }
}
