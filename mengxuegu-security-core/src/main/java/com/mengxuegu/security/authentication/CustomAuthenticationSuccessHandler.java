package com.mengxuegu.security.authentication;

import com.alibaba.fastjson.JSON;
import com.mengxuegu.base.result.MengxueguResult;
import com.mengxuegu.security.properties.LoginResponseType;
import com.mengxuegu.security.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author：wangn
 * @Date：2020/5/27
 * @Description：认证成功处理器
 * 1.决定响应json还是跳转页面，或者认证成功后进行其他处理
 **/
@Component("customAuthenticationSuccessHandler")
//public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler{

    Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    SecurityProperties securityProperties;

    /**
     * 认证成功后处理逻辑
     * @param authentication 封装了用户信息 UserDetails，访问IP等
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        if(LoginResponseType.JSON.equals( securityProperties.getAuthentication().getLoginType())) {
            // 认证成功后，响应JSON字符串
            MengxueguResult result = MengxueguResult.ok("认证成功");
            httpServletResponse.setContentType("application/json;charset=UTF-8");
            httpServletResponse.getWriter().write(result.toJsonString());
        }else {
            //重定向到上次请求的地址上，引发跳转到认证页面的地址
            logger.info("authentication: " + JSON.toJSONString(authentication));
            super.onAuthenticationSuccess(httpServletRequest, httpServletResponse, authentication);
        }
    }
}
