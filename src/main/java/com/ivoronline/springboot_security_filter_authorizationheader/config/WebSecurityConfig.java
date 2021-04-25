package com.ivoronline.springboot_security_filter_authorizationheader.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired MyFilter myFilter;

  //=================================================================
  // AUTHENTICATION MANAGER BEAN
  //=================================================================
  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  //=================================================================
  // USER DETAILS SERVICE
  //=================================================================
  @Bean
  @Override
  protected UserDetailsService userDetailsService() {

    //CREATE USERS
    UserDetails myuser  = User.withUsername("myuser" ).password("myuserpassword" ).roles("USER" ).build();
    UserDetails myadmin = User.withUsername("myadmin").password("myadminpassword").roles("ADMIN").build();

    //STORE USER
    return new InMemoryUserDetailsManager(myuser, myadmin);

  }

  //=======================================================================
  // PASSWORD ENCODER
  //=======================================================================
  @Bean
  PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  //=================================================================
  // CONFIGURE
  //=================================================================
  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //No Session
    httpSecurity.csrf().disable();                                                           //Enable POST
  }

}
