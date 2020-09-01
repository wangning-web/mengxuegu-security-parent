package com.mengxuegu.security.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @Author：wangn
 * @Date：2020/5/25
 * @Description：
 **/
@Component
@ConfigurationProperties( prefix = "mengxuegu.security")
public class SecurityProperties {

    // 将application.yml 中的 mengxuegu.security.authentication 下面的值绑定到此对象中
    private AuthenticationProperties authentication;

    public AuthenticationProperties getAuthentication() {
        return authentication;
    }

    public void setAuthentication(AuthenticationProperties authentication) {
        this.authentication = authentication;
    }

}
