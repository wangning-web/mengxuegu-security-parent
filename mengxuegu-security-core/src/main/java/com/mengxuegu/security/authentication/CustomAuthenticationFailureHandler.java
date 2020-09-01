package com.mengxuegu.security.authentication;

import com.mengxuegu.base.result.MengxueguResult;
import com.mengxuegu.security.properties.LoginResponseType;
import com.mengxuegu.security.properties.SecurityProperties;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author：wangn
 * @Date：2020/5/27
 * @Description：
 **/
@Component("customAuthenticationFailureHandler")
//public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    SecurityProperties securityProperties;

    /**
     * 认证失败时抛出异常
     * @param httpServletRequest
     * @param httpServletResponse
     * @param exception
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException exception) throws IOException, ServletException {
        if(LoginResponseType.JSON.equals( securityProperties.getAuthentication().getLoginType())) {
            // 认证失败响应JSON字符串，
            MengxueguResult result = MengxueguResult.build(HttpStatus.UNAUTHORIZED.value(), exception.getMessage());
            httpServletResponse.setContentType("application/json;charset=UTF-8");
            httpServletResponse.getWriter().write(result.toJsonString());
        }else {
            // 重写向回认证页面，注意加上 ?error
            //super.setDefaultFailureUrl( securityProperties.getAuthentication().getLoginPage()+"?error");
            // 获取上一次请求路径
            String referer = httpServletRequest.getHeader("Referer");
            logger.info("referer:" + referer);
            String lastUrl = StringUtils.substringBefore(referer,"?");
            logger.info("上一次请求的路径 ：" + lastUrl);
            super.setDefaultFailureUrl(lastUrl+"?error");
            super.onAuthenticationFailure(httpServletRequest, httpServletResponse, exception);
        }
    }
}
