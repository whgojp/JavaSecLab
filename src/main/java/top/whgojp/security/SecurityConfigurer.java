package top.whgojp.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import top.whgojp.common.config.AuthIgnoreConfig;
import top.whgojp.common.constant.SysConstant;
import top.whgojp.common.filter.ValidateCodeFilter;
import top.whgojp.common.push.service.EmailPush;
import top.whgojp.security.detail.CustomUserDetailsService;
import top.whgojp.security.handler.CustomLogoutSuccessHandler;
import top.whgojp.security.handler.CustomSavedRequestAwareAuthenticationSuccessHandler;
import top.whgojp.security.handler.CustomSimpleUrlAuthenticationFailureHandler;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthIgnoreConfig authIgnoreConfig;
    @Autowired
    private ValidateCodeFilter validateCodeFilter;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private CustomSessionInformationExpiredStrategy sessionInformationExpiredStrategy;

    @Autowired
    private EmailPush emailPush;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                // 不做具体的 AuthenticationManager 选择这里的默认使用 DaoAuthenticationConfigurer
                // 这个 DetailsService 单纯就是从 Dao 层取得用户数据，它不进行密码校验
                .userDetailsService(customUserDetailsService)   // 用户认证处理
                // 如果上面那个 userDetailsService 够简单其实可以像下面这样用 SQL 语句查询比对
                // .dataSource(dataSource)
                // .usersByUsernameQuery("Select * from users where username=?")
                // 这个 passwordEncoder 配置的实际就是 DaoAuthenticationConfigurer 的加密器
                .passwordEncoder(passwordEncoder());    // 密码处理

    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        List<String> permitAll = authIgnoreConfig.getIgnoreUrls();
        permitAll.add(SysConstant.LOGIN_URL);
        permitAll.add(SysConstant.LOGIN_PROCESS);
        permitAll.add(SysConstant.LOGOUT_URL);
        permitAll.add(SysConstant.JWT_AUTH);
        permitAll.add("/eureka/**");
        permitAll.add("/file/**");
        permitAll.add("/static/images/**");
        permitAll.add("/static/lib/**");
        permitAll.add("/static/js/**");
        permitAll.add("/static/css/**");
        permitAll.add("/static/other/**");
//        permitAll.add("/druid/**");
//        permitAll.add("/ueditor/**");
        String[] urls = permitAll.stream().distinct().toArray(String[]::new);


        http.headers()
                .frameOptions().disable();   // 禁用 X-Frame-Options

        // 权限
        http.authorizeRequests(authorize ->
                // 开放权限
                authorize.antMatchers(urls).permitAll()
                        .anyRequest().authenticated());

        // 使用jwt 关闭session校验
//        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

//        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        // 如果不需要验证码校验登录 可以注释掉该行
//        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class);

        // 如果不用验证码，注释这个过滤器即可
//        http.addFilterAt(usernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);


        // 添加session管理器 session失效后跳到登录页
        http.sessionManagement()
                .invalidSessionUrl(SysConstant.LOGIN_URL)
                .maximumSessions(1)
                .expiredSessionStrategy(sessionInformationExpiredStrategy);

        http.formLogin()
                .loginPage(SysConstant.LOGIN_URL)
                .loginProcessingUrl(SysConstant.LOGIN_PROCESS)
                .successHandler(authenticationSuccessHandler())
                .failureHandler(customSimpleUrlAuthenticationFailureHandler());


        http.logout()
                .logoutSuccessHandler(customLogoutSuccessHandler())
                .permitAll();

        // 跨域配置
        http.cors().configurationSource(corsConfigurationSource());

        // TODO: 2024/6/14 为什么这里 loginProcessingUrl 302跳转跟csrf有关系呢🤔️
        http.csrf().disable();

    }


    // 解决跨域
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();   // 为方便测试 使用明文密码 未进行加密加盐处理
    }


    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        CustomSavedRequestAwareAuthenticationSuccessHandler customSavedRequestAwareAuthenticationSuccessHandler = new CustomSavedRequestAwareAuthenticationSuccessHandler();
        customSavedRequestAwareAuthenticationSuccessHandler.setDefaultTargetUrl("/index");
        customSavedRequestAwareAuthenticationSuccessHandler.setEmailPush(emailPush);
//        customSavedRequestAwareAuthenticationSuccessHandler.setSmsService(smsService);
//        customSavedRequestAwareAuthenticationSuccessHandler.setWeChatService(wechatService);
        return customSavedRequestAwareAuthenticationSuccessHandler;
    }

//    @Bean
//    public JwtRequestFilter jwtRequestFilter() {
//        return new JwtRequestFilter();
//    }

    @Bean
    public LogoutSuccessHandler customLogoutSuccessHandler() {
        CustomLogoutSuccessHandler customLogoutSuccessHandler = new CustomLogoutSuccessHandler();
        customLogoutSuccessHandler.setDefaultTargetUrl(SysConstant.LOGIN_URL);
        customLogoutSuccessHandler.setEmailPush(emailPush);

        return customLogoutSuccessHandler;
    }

    public AuthenticationFailureHandler customSimpleUrlAuthenticationFailureHandler() {
        CustomSimpleUrlAuthenticationFailureHandler customSimpleUrlAuthenticationFailureHandler = new CustomSimpleUrlAuthenticationFailureHandler();
        customSimpleUrlAuthenticationFailureHandler.setDefaultFailureUrl(SysConstant.LOGIN_URL);
        customSimpleUrlAuthenticationFailureHandler.setEmailPush(emailPush);

        return customSimpleUrlAuthenticationFailureHandler;
    }


}