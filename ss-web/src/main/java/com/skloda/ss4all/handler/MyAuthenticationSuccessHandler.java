package com.skloda.ss4all.handler;

import com.alibaba.fastjson.JSON;
import com.skloda.ss4all.utils.HttpUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class MyAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (HttpUtils.isAjaxRequest(request)) {
            //这里可以根据实际情况，来确定是跳转到页面或者json格式。
            //如果是ajax方式登陆需要返回json格式，那么我们这么写
            Map<String, String> map = new HashMap<>();
            map.put("code", "200");
            map.put("msg", "登录成功");
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(JSON.toJSONString(map));
        }
        //如果是要直接处理跳转到某个页面直接使用下面方法
        //getRedirectStrategy().sendRedirect(request, response, "/index");

//        //解决ss5.0.x一个bug，访问默认登出地址/login?logout时被认为是访问资源被savedrequest记录origin url导致再次302回跳到登录页面
//        //如果配置logoutSuccessUrl和loginPage一直则无须该处理
//        String url = request.getRequestURL().toString();
//        if (url.endsWith("/login") || url.endsWith("/ipVerify"))
//            super.setAlwaysUseDefaultTargetUrl(true);
        super.onAuthenticationSuccess(request, response, authentication);
    }
}

