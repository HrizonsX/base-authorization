package io.github.opensabre.authorization.entity;

import io.github.opensabre.common.core.entity.vo.Result;
import io.github.opensabre.common.core.exception.ErrorType;

/**
 * 解决 Feign 调用完成后 创建结果对象抛 Result 无默认构造器异常
 *
 * @param <T>
 */
public class ExdResult<T> extends Result<T> {
    public ExdResult(ErrorType errorType) {
        super(errorType);
    }

    public ExdResult() {
        super(new ErrorType() {
            @Override
            public String getCode() {
                return SUCCESSFUL_CODE;
            }

            @Override
            public String getMesg() {
                return SUCCESSFUL_MESG;
            }
        }, null);
    }

    public ExdResult(ErrorType errorType, T data) {
        super(errorType, data);
    }
}
