//package com.example.demo.security;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//
//@Configuration
//public class SecurityConfigDeprecated extends WebSecurityConfigurerAdapter
//{
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception
//    {
//        http
//                .csrf().disable()//As API is not going to be used by the browsers so can disable this protection
//                .authorizeRequests()//First authorize request
//
//                .antMatchers(HttpMethod.GET, "/students").hasAnyRole("ADMIN", "GUEST")
//                .antMatchers(HttpMethod.POST, "/students").hasRole("ADMIN")
//                .anyRequest().authenticated()//Any request needs to be authenticated
//                .and()
//                .httpBasic()//We are going to authenticate the requests using basic authentication
//                .and()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);//Disable sessions
//    }
//
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth)
//            throws Exception
//    {
//        auth.inMemoryAuthentication()
//                .withUser("admin")
//                .password(passwordEncoder.encode("admin"))
//                .roles("ADMIN")
//                .and()
//                .withUser("guest")
//                .password(passwordEncoder.encode("guest"))
//                .roles("GUEST");
//    }
//}
//
