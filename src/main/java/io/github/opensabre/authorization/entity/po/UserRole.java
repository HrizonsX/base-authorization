package io.github.opensabre.authorization.entity.po;

import com.baomidou.mybatisplus.annotation.TableName;
import io.github.opensabre.common.web.entity.po.BasePo;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName(value = "base_org_user_role", autoResultMap = true)
public class UserRole extends BasePo {
    private String userId;
    private String roleId;
}
