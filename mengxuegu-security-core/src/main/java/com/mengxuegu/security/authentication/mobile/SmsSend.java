package com.mengxuegu.security.authentication.mobile;

/**
 * @Author：wangn
 * @Date：2020/5/28
 * @Description：
 **/
public interface SmsSend {
    boolean sendSms(String mobile, String content);
}
