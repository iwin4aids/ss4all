package com.skloda.ss4all.auth.ip;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 配置IP验证端点的过滤器
 */
public class IpAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    //使用/ipVerify该端点进行ip认证
    public IpAuthenticationProcessingFilter(String pattern) {
        super(new AntPathRequestMatcher(pattern));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        //获取host信息
        String host = request.getRemoteHost();
        //交给内部的AuthenticationManager去认证，实现解耦
        return getAuthenticationManager().authenticate(new IpAuthenticationToken(host));
    }
}
