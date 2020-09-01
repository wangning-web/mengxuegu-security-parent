package com.mengxuegu.security.authentication.mobile;

import com.mengxuegu.security.authentication.CustomAuthenticationFailureHandler;
import com.mengxuegu.security.authentication.exception.ValidateCodeException;
import com.mengxuegu.security.controller.MobileLoginController;
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
 * @Description：校验用户输入的手机验证码是否正确
 **/
@Component
public class MobileValidateFilter extends OncePerRequestFilter {

    @Autowired
    CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        if("/mobile/form".equals(httpServletRequest.getRequestURI())
                && "post".equalsIgnoreCase(httpServletRequest.getMethod())) {
            try {
                // 校验验证码合法性
                validate(httpServletRequest);
            }catch (AuthenticationException e) {
                // 交给失败处理器进行处理异常
            customAuthenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
            // 一定要记得结束
            return;
            }
        }
        // 非手机验证码登录，则直接放行
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void validate(HttpServletRequest request) {
        // 先获取seesion中的验证码
        String sessionCode = (String)request.getSession().getAttribute(MobileLoginController.SESSION_KEY);
        // 获取用户输入的验证码
        String inpuCode = request.getParameter("code");
        // 判断是否正确
        if(StringUtils.isBlank(inpuCode)) {
            throw new ValidateCodeException("短信验证码不能为空");
        }
        if(!inpuCode.equalsIgnoreCase(sessionCode)) {
            throw new ValidateCodeException("短信验证码输入错误");
        }
    }

}
