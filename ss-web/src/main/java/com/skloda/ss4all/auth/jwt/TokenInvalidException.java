package com.skloda.ss4all.auth.jwt;

import org.springframework.security.core.AuthenticationException;

/**
 * Author: jiangkun
 * Date: Created on 2021/12/14 15:14
 * Description:
 */
public class TokenInvalidException extends AuthenticationException {
    public TokenInvalidException(String msg) {
        super(msg);
    }
}
