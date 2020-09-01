package com.mengxuegu.security.config;

import com.mengxuegu.security.authentication.code.ImageCodeValidateFilter;
import com.mengxuegu.security.authentication.mobile.MobileAuthenticationConfig;
import com.mengxuegu.security.authentication.mobile.MobileValidateFilter;
import com.mengxuegu.security.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.sql.DataSource;

/**
 * @Author：wangn
 * @Date：2020/5/23
 * @Description：
 **/
@Configuration
@EnableWebSecurity //启动 SpringSecurity 过滤器链功能
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private UserDetailsService customUserDetailsService;

    // 验证码校验过滤器
    @Autowired
    private ImageCodeValidateFilter imageCodeValidateFilter;

    // 注入自定义的认证成功处理器
    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    // 注入自定义的认证失败处理器
    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;

    //用于校验用户手机号是否允许通过认证
    @Autowired
    private MobileValidateFilter mobileValidateFilter;

    //用于组合其他关于手机登录的组件
    @Autowired
    private MobileAuthenticationConfig mobileAuthenticationConfig;

    // 记住我功能
    @Autowired
    private DataSource dataSource;

    @Bean
    public JdbcTokenRepositoryImpl jdbcTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        // 是否启动时自动创建表，第一次启动创建就行，后面启动把这个注释掉,不然报错已存在表
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 认证管理器：
     * 1、认证信息提供方式（用户名、密码、当前用户的资源权限）
     * 2、可采用内存存储方式，也可能采用数据库方式等
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //String password = passwordEncoder().encode("123456");
        //logger.info("加密之后的密码："+password);

        //数据库存储的密码必须是加密的，不然会报错There is no PasswordEncoder mapped for the id "null"
        //auth.inMemoryAuthentication().withUser("mengxuegu").password(password).authorities("ADMIN");
        // 用户信息存储在数据库中
        auth.userDetailsService(customUserDetailsService);
    }

    /**
     * 资源权限配置（过滤器链）:
     * 1、被拦截的资源
     * 2、资源所对应的角色权限
     * 3、定义认证方式：httpBasic 、httpForm
     * 4、定制登录页面、登录请求地址、错误处理方式
     * 5、自定义 spring security 过滤器
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //http.httpBasic()
        http.addFilterBefore(mobileValidateFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(imageCodeValidateFilter, UsernamePasswordAuthenticationFilter.class)
        .formLogin()//表单登陆方式
        .loginPage(securityProperties.getAuthentication().getLoginPage())// 交给 /login/page 响应认证(登录)页面
        .loginProcessingUrl(securityProperties.getAuthentication().getLoginProcessingUrl()) // 登录表单提交处理Url, 默认是 /login
        .usernameParameter(securityProperties.getAuthentication().getUsernameParameter()) // 默认用户名的属性名是 username
        .passwordParameter(securityProperties.getAuthentication().getPasswordParameter()) // 默认密码的属性名是 password
        .successHandler(customAuthenticationSuccessHandler) // 认证成功处理器
        .failureHandler(customAuthenticationFailureHandler) // 认证失败处理器
        .and()
        .authorizeRequests() // 认证请求
        .antMatchers(securityProperties.getAuthentication().getLoginPage(),"/code/image", "/mobile/page", "/code/mobile").permitAll() // 放行跳转认证请求，所有的
        .anyRequest().authenticated() // 所有进入应用的HTTP请求都要进行认证
        .and()
        .rememberMe() //记住我
        .tokenRepository(jdbcTokenRepository()) // 保存登录信息
        .tokenValiditySeconds(60*60*24*7) // 记住我有效时长（秒）
        ; // 分号`;`不要少了

        // 将手机相关的配置绑定过滤器链上
        http.apply(mobileAuthenticationConfig);
    }


    /**
     * 一般针对静态资源放行
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers(securityProperties.getAuthentication().getStaticPaths());
    }
}
