package com.skloda.ss4all.auth.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Author: jiangkun
 * Date: Created on 2021/12/13 18:36
 * Description:
 */
public class JwtTokenAuthentication extends AbstractAuthenticationToken {

    private final String username;
    private final String token;

    // 未认证时
    public JwtTokenAuthentication(String username, String token) {
        super(null);
        this.username = username;
        this.token = token;
        super.setAuthenticated(false);
    }

    // 认证后
    public JwtTokenAuthentication(String username, String token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.username = username;
        this.token = token;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.token;
    }

    @Override
    public Object getPrincipal() {
        return this.username;
    }
}
