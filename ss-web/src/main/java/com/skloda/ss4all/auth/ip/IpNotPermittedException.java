package com.skloda.ss4all.auth.ip;

import org.springframework.security.core.AuthenticationException;

/**
 * 自定义IP登陆异常
 */
public class IpNotPermittedException extends AuthenticationException {

    public IpNotPermittedException(String msg) {
        super(msg);
    }

    public IpNotPermittedException(String msg, Throwable t) {
        super(msg, t);
    }
}
