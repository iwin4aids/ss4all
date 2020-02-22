package com.skloda.ss4all.auth.userpwd;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * 根据用户名加载用户主体信息的简单实现
 */
@Component
public class SimpleUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username.equals("admin")) {
            //假设返回的用户信息如下;
            return new UserInfo("admin", "123456", "ROLE_ADMIN", true, true, true, true);
        }
        throw new UsernameNotFoundException("user:" + username + " not found");
    }
}
