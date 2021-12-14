package com.skloda.ss4all.auth.jwt;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

/**
 * Author: jiangkun
 * Date: Created on 2021/12/13 18:36
 * Description:
 */
@Component("jwtAuthenticationProvider")
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtTokenAuthentication jwtTokenAuthentication = (JwtTokenAuthentication) authentication;
        String username = (String) jwtTokenAuthentication.getPrincipal();
        String token = (String) jwtTokenAuthentication.getCredentials();
        try {
            if (JwtUtils.isJwtTokenExpired(token))
                throw new TokenInvalidException("token已过期，请重新获取!");
        } catch (Exception e) {
            e.printStackTrace();
            throw new TokenInvalidException("非法token!");
        }
        return new JwtTokenAuthentication(username, token, AuthorityUtils.commaSeparatedStringToAuthorityList(JwtUtils.getUserRoleFromToken(token)));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtTokenAuthentication.class.isAssignableFrom(authentication);
    }
}
