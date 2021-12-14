package com.skloda.ss4all.auth.ip;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IP认证实现
 */
@Component
public class IpAuthenticationProvider implements AuthenticationProvider {

    final static Map<String, String> ipAuthorityMap = new ConcurrentHashMap<>();

    //维护一个ip白名单列表，每个ip对应一定的权限
    static {
        ipAuthorityMap.put("0:0:0:0:0:0:0:1", "ADMIN");
        ipAuthorityMap.put("127.0.0.1", "ADMIN");
        ipAuthorityMap.put("10.164.84.78", "SELLER,STAFF");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        IpAuthentication ipAuthentication = (IpAuthentication) authentication;
        String ip = ipAuthentication.getIp();
        System.out.println("客户端使用IP登陆，当前登陆的IP：" + ip);
        String stringAuthorities = ipAuthorityMap.get(ip);
        //不在白名单列表中
        if (stringAuthorities == null) {
            throw new IpNotPermittedException("当前IP[" + ip + "]未被授权访问!");
        } else {
            //封装权限信息，并且此时身份已经被认证
            return new IpAuthentication(ip, AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities));
        }
    }

    //只支持IpAuthenticationToken该身份
    @Override
    public boolean supports(Class<?> authentication) {
        return IpAuthentication.class.isAssignableFrom(authentication);
    }
}
