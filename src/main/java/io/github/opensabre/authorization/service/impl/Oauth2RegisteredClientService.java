package io.github.opensabre.authorization.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.github.opensabre.authorization.dao.RegisteredClientMapper;
import io.github.opensabre.authorization.entity.RegisteredClientConvert;
import io.github.opensabre.authorization.entity.param.RegisteredClientQueryParam;
import io.github.opensabre.authorization.entity.po.RegisteredClientPo;
import io.github.opensabre.authorization.entity.vo.RegisteredClientVo;
import io.github.opensabre.authorization.service.IOauth2RegisteredClientService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class Oauth2RegisteredClientService extends ServiceImpl<RegisteredClientMapper, RegisteredClientPo> implements IOauth2RegisteredClientService {

    @Resource
    PasswordEncoder passwordEncoder;

    @Resource
    RegisteredClientConvert registeredClientConvert;

    @Override
    public boolean add(RegisteredClientPo registeredClientPo) {
        // 密码不为空，表示重新设置了密码，需要保存密码
        if (StringUtils.isNotBlank(registeredClientPo.getClientSecret()))
            registeredClientPo.setClientSecret(passwordEncoder.encode(registeredClientPo.getClientSecret()));
        return this.save(registeredClientPo);
    }

    @Override
    public boolean update(RegisteredClientPo registeredClientPo) {
        // 密码不为空，表示重新设置了密码，需要更新密码
        if (StringUtils.isNotBlank(registeredClientPo.getClientSecret()))
            registeredClientPo.setClientSecret(passwordEncoder.encode(registeredClientPo.getClientSecret()));
        return this.updateById(registeredClientPo);
    }

    @Override
    public IPage<RegisteredClientVo> query(Page page, RegisteredClientQueryParam registeredClientQueryParam) {
        QueryWrapper<RegisteredClientPo> queryWrapper = registeredClientQueryParam.build();
        queryWrapper.eq(StringUtils.isNotBlank(registeredClientQueryParam.getClientId()), "client_id", registeredClientQueryParam.getClientId());
        queryWrapper.eq(StringUtils.isNotBlank(registeredClientQueryParam.getClientName()), "client_name", registeredClientQueryParam.getClientName());
        IPage<RegisteredClientPo> iPage = page(page, queryWrapper);
        return iPage.convert(registeredClientConvert::convertToRegisteredClientVo);
    }

    @Override
    public RegisteredClientPo get(String id) {
        return this.getById(id);
    }

    @Override
    public RegisteredClientPo getByClientId(String clientId) {
        QueryWrapper<RegisteredClientPo> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("client_id", clientId);
        return this.getOne(queryWrapper);
    }

    @Override
    public boolean disable(String id) {
        return this.removeById(id);
    }
}
