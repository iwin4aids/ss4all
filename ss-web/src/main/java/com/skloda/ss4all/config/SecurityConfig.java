package com.skloda.ss4all.config;

import com.skloda.ss4all.auth.ip.IpAuthenticationProcessingFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // remember-me对应cookie中的key
    private static final String REMEMBER_ME_KEY = "my-remember-me-key";

    private final AuthenticationSuccessHandler myAuthenticationSuccessHandler;

    private final AuthenticationFailureHandler myAuthenticationFailHander;

    private final AccessDeniedHandler accessDeniedHandler;

    private final AuthenticationProvider usernamePasswordAuthenticationProvider;

    private final AuthenticationProvider ipAuthenticationProvider;

    private final UserDetailsService userDetailsService;

    public SecurityConfig(AuthenticationSuccessHandler myAuthenticationSuccessHandler, AuthenticationFailureHandler myAuthenticationFailHander, AccessDeniedHandler accessDeniedHandler, @Qualifier("usernamePasswordAuthenticationProvider") AuthenticationProvider usernamePasswordAuthenticationProvider, @Qualifier("ipAuthticationProvider") AuthenticationProvider ipAuthenticationProvider, UserDetailsService userDetailsService) {
        this.myAuthenticationSuccessHandler = myAuthenticationSuccessHandler;
        this.myAuthenticationFailHander = myAuthenticationFailHander;
        this.accessDeniedHandler = accessDeniedHandler;
        this.usernamePasswordAuthenticationProvider = usernamePasswordAuthenticationProvider;
        this.ipAuthenticationProvider = ipAuthenticationProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
        http.formLogin()
                //默认loginProcessUrl是post方式的"/login"，默认failureUrl和logoutSuccessUrl是"/login?error"和"/login?logout"
                .loginPage("/login").permitAll()
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailHander)
                .failureUrl("/login")
                .and().logout().logoutSuccessUrl("/login").logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                //.and().sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true).and() //并发登录控制
                .and().rememberMe().userDetailsService(userDetailsService).rememberMeServices(rememberMeServices())
                //.and().exceptionHandling().accessDeniedHandler(accessDeniedHandler) //自定义访问拒绝处理器
                .and().authorizeRequests().anyRequest().authenticated()
                //csrf默认开启的，但可以指定哪些pattern不被csrf保护
                .and().csrf().ignoringAntMatchers("/api/**", "/login", "/ipVerify")
                //自定义一个异常处理器
                .and().exceptionHandling().accessDeniedHandler(accessDeniedHandler)
                //注册IpAuthenticationProcessingFilter  注意放置的顺序这很关键，UsernamePasswordAuthenticationFilter是SS内置的
                .and().addFilterBefore(ipAuthenticationProcessingFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }

    //配置封装ipAuthenticationToken的过滤器
    private IpAuthenticationProcessingFilter ipAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
        IpAuthenticationProcessingFilter ipAuthenticationProcessingFilter = new IpAuthenticationProcessingFilter("/ipVerify");
        //为过滤器添加认证器
        ipAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager);
        //重写认证失败时的处理器
        ipAuthenticationProcessingFilter.setAuthenticationFailureHandler(myAuthenticationFailHander);
        //重写认证成功时的处理器
        ipAuthenticationProcessingFilter.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler);
        return ipAuthenticationProcessingFilter;
    }

    /**
     * 添加authenticationProvider，ss的抽象层次和扩展性体现
     * 支持多种身份认证提供方式，只要满足一种即可，如用户名密码、指纹、ip、二维码等等
     * @param auth
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(usernamePasswordAuthenticationProvider);//普通的用户名密码身份验证
        auth.authenticationProvider(ipAuthenticationProvider);//额外添加一个IP身份验证
        auth.authenticationProvider(new RememberMeAuthenticationProvider(REMEMBER_ME_KEY));
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/style/**", "/js/**", "/img/**", "/favicon.ico");
    }

    /**
     * 内置实现基于客户端cookie加密存储remember-me token
     * token加密方式：base64(username + ":" + expirationTime + ":" + md5Hex(username + ":" + expirationTime + ":" password + ":" + key))
     * 大规模使用建议使用持久化的存储如db，redis
     * @return
     */
    public RememberMeServices rememberMeServices() {
        TokenBasedRememberMeServices rememberMeServices = new TokenBasedRememberMeServices(REMEMBER_ME_KEY, userDetailsService);
        rememberMeServices.setTokenValiditySeconds(60); //默认是2周，这里模拟一分钟remember-me失效
        return rememberMeServices;
    }
}
