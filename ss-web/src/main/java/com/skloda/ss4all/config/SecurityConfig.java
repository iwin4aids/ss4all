package com.skloda.ss4all.config;

import com.skloda.ss4all.auth.ip.IpAuthenticationFilter;
import com.skloda.ss4all.auth.jwt.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
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

    // 每一类filter都可以定义自己的成功和失败处理器
    // 这里定义2个通用的成功和失败处理器，所以filter共享
    @Autowired
    @Qualifier("myAuthenticationSuccessHandler")
    private AuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Autowired
    @Qualifier("myAuthenticationFailHandler")
    private AuthenticationFailureHandler myAuthenticationFailHandler;

    @Autowired
    @Qualifier("jwtAuthenticationSuccessHandler")
    private AuthenticationSuccessHandler jwtAuthenticationSuccessHandler;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired
    private AuthenticationProvider usernamePasswordAuthenticationProvider;

    @Autowired
    private AuthenticationProvider ipAuthenticationProvider;

    @Autowired
    private AuthenticationProvider jwtAuthenticationProvider;

    @Qualifier("simpleUserDetailsService")
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
        http.formLogin()
                //默认loginProcessUrl是post方式的"/login"，默认failureUrl和logoutSuccessUrl是"/login?error"和"/login?logout"
                .loginPage("/login").permitAll()
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailHandler)
                //.failureUrl("/login")
                .and().logout().logoutSuccessUrl("/login").logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                //.and().sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true).and() //并发登录控制
                .and().rememberMe().userDetailsService(userDetailsService).rememberMeServices(rememberMeServices())
                //.and().exceptionHandling().accessDeniedHandler(accessDeniedHandler) //自定义访问拒绝处理器
                .and().authorizeRequests()
                // 指定某些url完全放开，可以配合controller注解获取元数据
                .antMatchers("/doc.html", "/swagger-resources/**").permitAll()
                .anyRequest().authenticated()
                //csrf默认开启的，但可以指定哪些pattern不被csrf保护
                .and().csrf().ignoringAntMatchers("/api/**", "/login", "/ipVerify")
                //自定义一个异常处理器
                .and().exceptionHandling().accessDeniedHandler(accessDeniedHandler)
                //注册IpAuthenticationProcessingFilter  注意放置的顺序这很关键，UsernamePasswordAuthenticationFilter是SS内置的
                //过滤器可以按顺序添加，如添加验证码的过滤器
                .and()
                .addFilterBefore(ipAuthenticationProcessingFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }

    //配置封装ipAuthenticationToken的过滤器
    private IpAuthenticationFilter ipAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
        IpAuthenticationFilter ipAuthenticationProcessingFilter = new IpAuthenticationFilter("/ipVerify");
        //为过滤器添加认证器
        ipAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager);
        //重写认证失败时的处理器
        ipAuthenticationProcessingFilter.setAuthenticationFailureHandler(myAuthenticationFailHandler);
        //重写认证成功时的处理器
        ipAuthenticationProcessingFilter.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler);
        return ipAuthenticationProcessingFilter;
    }

    //配置封装ipAuthenticationToken的过滤器
    private JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter("/api/**");
        //为过滤器添加认证器
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager);
        //重写认证失败时的处理器
        jwtAuthenticationFilter.setAuthenticationFailureHandler(myAuthenticationFailHandler);
        //重写认证成功时的处理器
        jwtAuthenticationFilter.setAuthenticationSuccessHandler(jwtAuthenticationSuccessHandler);
        return jwtAuthenticationFilter;
    }

    /**
     * 添加authenticationProvider，ss的抽象层次和扩展性体现
     * 支持多种身份认证提供方式，只要满足一种即可，如用户名密码、jwt token、指纹、ip、二维码等等
     *
     * @param auth 认证管理器构造器
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(usernamePasswordAuthenticationProvider);//普通的用户名密码身份验证
        auth.authenticationProvider(ipAuthenticationProvider);//额外添加一个IP身份验证器
        auth.authenticationProvider(jwtAuthenticationProvider);//额外添加一个jwt验证器
        auth.authenticationProvider(new RememberMeAuthenticationProvider(REMEMBER_ME_KEY));
    }

    /**
     * web资源单独处理
     *
     * @param webSecurity
     */
    @Override
    public void configure(WebSecurity webSecurity) {
        webSecurity.ignoring().antMatchers("/style/**", "/js/**", "/img/**", "/favicon.ico");
    }

    /**
     * 内置实现基于客户端cookie加密存储remember-me token
     * token加密方式：base64(username + ":" + expirationTime + ":" + md5Hex(username + ":" + expirationTime + ":" password + ":" + key))
     * 大规模使用建议使用持久化的存储如db，redis
     *
     * @return
     */
    public RememberMeServices rememberMeServices() {
        TokenBasedRememberMeServices rememberMeServices = new TokenBasedRememberMeServices(REMEMBER_ME_KEY, userDetailsService);
        rememberMeServices.setTokenValiditySeconds(60); //默认是2周，这里模拟一分钟remember-me失效
        return rememberMeServices;
    }
}
