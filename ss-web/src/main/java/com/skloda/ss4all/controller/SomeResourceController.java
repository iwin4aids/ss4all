package com.skloda.ss4all.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import java.util.Date;

/**
 * 模拟一些资源的controller
 */
@Controller
public class SomeResourceController {

    @PostMapping("/time")
    @ResponseBody
    public String getTime() {
        return "This is server time : " + new Date();
    }

    @GetMapping("/hello")
    public ModelAndView hello() {
        ModelAndView mv = new ModelAndView("hello");
        //Spring Security获取当前用户的方式，可以进行Util封装
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        mv.addObject("user", userDetails);
        mv.addObject("data", "This is a protected resources!");
        return mv;
    }
}
