package io.github.opensabre.authorization.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.github.opensabre.authorization.dao.UserMapper;
import io.github.opensabre.authorization.entity.User;
import io.github.opensabre.authorization.service.IUserRoleService;
import io.github.opensabre.authorization.service.IUserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Objects;

@Service
public class UserService extends ServiceImpl<UserMapper, User> implements IUserService {

    @Resource
    private IUserRoleService userRoleService;

    @Override
    public User getByUniqueId(String uniqueId) {
        User user = this.getOne(new QueryWrapper<User>()
                .eq("username", uniqueId)
                .or()
                .eq("mobile", uniqueId));
        if (Objects.isNull(user)) {
            return new User();
        }
        // 查询用户与角色关系信息
        user.setRoleIds(userRoleService.queryByUserId(user.getId()));
        return user;
    }
}
