package io.github.opensabre.authorization.service;

import java.util.Set;

public interface IUserRoleService {

    /**
     * 根据userId查询用户拥有角色id集合
     *
     * @param userId
     * @return
     */
    Set<String> queryByUserId(String userId);
}
