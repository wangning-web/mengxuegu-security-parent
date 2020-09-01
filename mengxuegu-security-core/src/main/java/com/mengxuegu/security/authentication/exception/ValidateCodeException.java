package com.mengxuegu.security.authentication.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @Author：wangn
 * @Date：2020/5/28
 * @Description：
 **/
public class ValidateCodeException extends AuthenticationException {
    public ValidateCodeException(String msg, Throwable t) {
        super(msg, t);
    }

    public ValidateCodeException(String msg) {
        super(msg);
    }
}
