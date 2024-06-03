package io.github.opensabre.authorization.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.github.opensabre.authorization.dao.RoleMapper;
import io.github.opensabre.authorization.entity.Role;
import io.github.opensabre.authorization.service.IRoleService;
import io.github.opensabre.authorization.service.IUserRoleService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.Set;

@Service
public class RoleService extends ServiceImpl<RoleMapper, Role> implements IRoleService {

    @Resource
    private IUserRoleService userRoleService;

    @Override
    public Set<Role> queryUserRolesByUserId(String userId) {
        Set<String> roleIds = userRoleService.queryByUserId(userId);
        Set<Role> roles = new HashSet<>();
        roles.addAll(listByIds(roleIds));
        return roles;
    }
}
