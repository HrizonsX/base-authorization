package io.github.opensabre.authorization.entity;

import io.github.opensabre.common.core.entity.vo.Result;
import io.github.opensabre.common.core.exception.ErrorType;

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
