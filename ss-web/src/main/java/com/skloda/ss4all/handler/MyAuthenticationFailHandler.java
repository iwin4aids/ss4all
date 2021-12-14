package com.skloda.ss4all.handler;

import com.alibaba.fastjson.JSON;
import com.skloda.ss4all.utils.HttpUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component("myAuthenticationFailHandler")
public class MyAuthenticationFailHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        System.out.println("onAuthenticationFailure");
        if(HttpUtils.isAjaxRequest(request)) {
            // 以Json格式返回
            Map<String, String> map = new HashMap<>();
            map.put("code", "-99");
            map.put("msg", exception.getLocalizedMessage());
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(JSON.toJSONString(map));
            return;
        }
        super.setDefaultFailureUrl("/login");
        super.onAuthenticationFailure(request, response, exception);
    }
}
