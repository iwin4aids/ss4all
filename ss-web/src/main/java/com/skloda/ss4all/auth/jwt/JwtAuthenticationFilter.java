package com.skloda.ss4all.auth.jwt;

import io.micrometer.core.instrument.util.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Author: jiangkun
 * Date: Created on 2021/12/13 18:35
 * Description:
 */
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final static String TOKEN_HEAD = "Bearer ";

    public JwtAuthenticationFilter(String pattern) {
        super(new AntPathRequestMatcher(pattern));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        String token = httpServletRequest.getHeader("Authorization");
        //获取host信息
        if (StringUtils.isNotBlank(token) && token.startsWith(TOKEN_HEAD)) {
            //如果header中存在token，则覆盖掉url中的token
            token = token.substring(TOKEN_HEAD.length()); // "Bearer "之后的内容
        }
        //交给内部的AuthenticationManager去认证，实现解耦
        return getAuthenticationManager().authenticate(new JwtTokenAuthentication(null, token));
    }
}
