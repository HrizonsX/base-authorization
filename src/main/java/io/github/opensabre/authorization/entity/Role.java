package io.github.opensabre.authorization.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import io.github.opensabre.common.web.entity.po.BasePo;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper = false )
@NoArgsConstructor
@TableName(value = "base_org_role", autoResultMap = true)
public class Role extends BasePo {
    private String code;
    private String name;
    private String description;
}
