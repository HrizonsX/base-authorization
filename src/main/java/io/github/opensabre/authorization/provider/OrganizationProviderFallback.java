package io.github.opensabre.authorization.provider;

import io.github.opensabre.authorization.entity.ExdResult;
import io.github.opensabre.authorization.entity.Role;
import io.github.opensabre.authorization.entity.User;
import io.github.opensabre.common.core.entity.vo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
public class OrganizationProviderFallback implements OrganizationProvider {

    @Override
    public ExdResult<User> getUserByUniqueId(String uniqueId) {
        log.warn("getUserByUniqueId downgrade");
        return (ExdResult) Result.success(new User());
    }

    @Override
    public ExdResult<Set<Role>> queryRolesByUserId(String userId) {
        log.warn("queryRolesByUserId downgrade");
        return (ExdResult) Result.success(new HashSet<Role>());
    }
}
