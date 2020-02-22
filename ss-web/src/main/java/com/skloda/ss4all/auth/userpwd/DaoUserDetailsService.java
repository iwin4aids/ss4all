package com.skloda.ss4all.auth.userpwd;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * 从数据库中获取用户主体信息
 */
public class DaoUserDetailsService implements UserDetailsService {

    //注入userService,roleService等对象

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //TODO 调用方法查询数据库（缓存），构造出UserDetails对象
        return null;
    }
}
