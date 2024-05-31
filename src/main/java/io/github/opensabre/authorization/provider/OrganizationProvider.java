package io.github.opensabre.authorization.provider;

import io.github.opensabre.authorization.entity.ExdResult;
import io.github.opensabre.authorization.entity.Role;
import io.github.opensabre.authorization.entity.User;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Set;

@FeignClient(name = "base-node")
public interface OrganizationProvider {

    @GetMapping(value = "/user")
    ExdResult<User> getUserByUniqueId(@RequestParam("uniqueId") String uniqueId);

    @GetMapping(value = "/role/user/{userId}")
    ExdResult<Set<Role>> queryRolesByUserId(@PathVariable("userId") String userId);
}
