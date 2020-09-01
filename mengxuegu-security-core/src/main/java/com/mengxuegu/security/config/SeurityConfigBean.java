package com.mengxuegu.security.config;

import com.mengxuegu.security.authentication.mobile.SmsCodeSender;
import com.mengxuegu.security.authentication.mobile.SmsSend;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @Author：wangn
 * @Date：2020/5/28
 * @Description：主要为容器中添加bean实例
 **/
@Configuration
public class SeurityConfigBean {

    /**
     * @ConditionalOnMissingBean(SmsSend.class)
     * 默认采用SmsCodeSender实例 ，但如果容器中有其他 SmsSend 类型的实例，则当前实例失效
     */
    @Bean
    @ConditionalOnMissingBean(SmsSend.class)
    public SmsSend smsSend(){
        return new SmsCodeSender();
    }

}
