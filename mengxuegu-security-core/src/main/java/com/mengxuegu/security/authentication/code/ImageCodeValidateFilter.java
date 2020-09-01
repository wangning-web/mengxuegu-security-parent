package com.mengxuegu.security.authentication.code;

import com.mengxuegu.security.authentication.CustomAuthenticationFailureHandler;
import com.mengxuegu.security.authentication.exception.ValidateCodeException;
import com.mengxuegu.security.controller.CustomLoginController;
import com.mengxuegu.security.properties.SecurityProperties;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author：wangn
 * @Date：2020/5/28
 * @Description：OncePerRequestFilter: 所有请求之前被调用一次
 **/
@Component("imageCodeValidateFilter")
public class ImageCodeValidateFilter extends OncePerRequestFilter {

    @Autowired
    SecurityProperties securityProperties;
    @Autowired
    CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        //1. 如果是post方式 的登录请求，则校验输入的验证码是否正确
        if(securityProperties.getAuthentication().getLoginProcessingUrl().equals(httpServletRequest.getRequestURI())
                && httpServletRequest.getMethod().equalsIgnoreCase("post")){
            try {
                // 校验验证码合法性
                validate(httpServletRequest);
            }catch (AuthenticationException e){
                //交给失败处理器进行异常处理
                customAuthenticationFailureHandler.onAuthenticationFailure(httpServletRequest,httpServletResponse,e);
                //一定要记得结束
                return;
            }

        }
        //放行请求
        filterChain.doFilter(httpServletRequest, httpServletResponse);

    }

    private void validate(HttpServletRequest httpServletRequest){
        //先获取seesion中的验证码
        String sessionCode = (String)httpServletRequest.getSession().getAttribute(CustomLoginController.SESSION_KEY);
        // 获取用户输入的验证码
        String inpuCode = httpServletRequest.getParameter("code");
        // 判断是否正确
        if(StringUtils.isBlank(inpuCode)) {
            throw new ValidateCodeException("验证码不能为空");
        }
        if(!inpuCode.equalsIgnoreCase(sessionCode)) {
            throw new ValidateCodeException("验证码输入错误");
        }

    }
}
