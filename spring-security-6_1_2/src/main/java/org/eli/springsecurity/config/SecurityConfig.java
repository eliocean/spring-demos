package org.eli.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /*
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .requestMatchers("/resources/**");
    }
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 路径权限
        http
                .authorizeHttpRequests((authorizeHttpRequests) ->
                                authorizeHttpRequests
                                        .requestMatchers("/login").permitAll()
                                        .anyRequest().authenticated()
//                                .requestMatchers("/**").hasAnyRole("ADMIN","USER")
//                                .requestMatchers("/admin/**").hasRole("ADMIN")
                );

        // 异常处理
        http.exceptionHandling((exceptionHandling) ->exceptionHandling
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.setContentType("text/html;charset=UTF-8");
                        response.getWriter().write("access denied!");
                        log.error("access denied exception = {}", accessDeniedException);
                        accessDeniedException.printStackTrace();
                    }
                })
        );


        // 登录
        http.formLogin((formLogin) -> formLogin
//                .loginPage("/login")
//                        .loginProcessingUrl("/login")
//                .defaultSuccessUrl("/index")
                        .successHandler(new LoginSuccessHandler())
                        .failureHandler(new LoginFailureHandler())
        );

        // csrf 设置
        http.csrf(Customizer.withDefaults()); // 使用默认设置，默认disable()
//        http.csrf((csrf) -> csrf.disable()); // 禁用csrf，禁用跨域拦截

        return http.build();
    }


    /*

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN", "USER")
                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }
    */
}

/**
 * @ Description: 登录成功处理器
 * @ Author: zxhacker
 * @ CreateTime: 2024-04-29 20:15
 **/
@Slf4j
class LoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("login success!");
        log.debug("authentication.getPrincipal() = {}", authentication.getPrincipal());
        log.debug("authentication.getAuthorities() = {}", authentication.getAuthorities());
        log.debug("authentication.getCredentials() = {}", authentication.getCredentials());
    }
}

/**
 * @ Description: 登录失败处理器
 * @ Author: zxhacker
 * @ CreateTime: 2024-04-29 20:16
 **/
@Slf4j
class LoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("login failure!");
        log.error("login exception = {}", exception);
        exception.printStackTrace();
    }

}