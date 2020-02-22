package com.skloda.ss4all.auth.userpwd;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 最常用的用户名密码登陆方式，token已有实现类UsernamePasswordAuthenticationToken
 * spring security 已经非常抽象的实现了用户名密码登录的主体逻辑（模板方法模式）
 * 继承该抽象类非常方便，通常只需要覆盖抽象类中的2个方法即可
 */
@Component
public class UsernamePasswordAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    /**
     * 可以不隐藏用户不存在这个异常
     */
    public UsernamePasswordAuthenticationProvider(@Qualifier("simpleUserDetailsService") UserDetailsService userDetailService) {
        this.setHideUserNotFoundExceptions(false);
        this.userDetailService = userDetailService;
    }

    /**
     * 注入我们自己定义的用户信息获取对象
     */
    private final UserDetailsService userDetailService;

    /**
     * 子类实现自己check逻辑
     */
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        System.out.println("客户端使用用户名密码登陆,登录名：" + userDetails.getUsername());
        //BCrypt比MD5+盐更安全，每次Hash的结果不一致，但是每种hash结果和原始数据match都可以验证成功
        if (!bCryptPasswordEncoder.matches(userDetails.getPassword(), bCryptPasswordEncoder.encode((String) authentication.getCredentials()))) {
            throw new BadCredentialsException(messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
    }

    /**
     * 子类实现自己的如何加载用户信息方法
     */
    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // 这里调用我们的自己写的获取用户的方法
        return userDetailService.loadUserByUsername(username);
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String encrypt_pwd1 = bCryptPasswordEncoder.encode("123456");
        String encrypt_pwd2 = bCryptPasswordEncoder.encode("123456");

        System.out.println(encrypt_pwd1);
        System.out.println(encrypt_pwd2);
        System.out.println(bCryptPasswordEncoder.matches("123456", encrypt_pwd1));
        System.out.println(bCryptPasswordEncoder.matches("123456", encrypt_pwd2));
    }

}
