package com.ivoronline.springboot_security_filter_authorizationheader.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class MyFilter implements Filter {

  @Autowired AuthenticationManager authenticationManager;

  //========================================================================
  // AUTHENTICATE
  //========================================================================
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterchain)
    throws IOException, ServletException {

    //CAST TO GET ACCESS TO HEADERS
    HttpServletRequest httpRequest = (HttpServletRequest) request;

    //GET AUTHORIZATION HEADER
    String authorization = httpRequest.getHeader("Authorization");    //Basic bXl1c2VyOm15dXNlcnBhc3N3b3Jk

    //GET CREDENTIALS
    String   credEncoded = authorization.split(" ")[1];                     //bXl1c2VyOm15dXNlcnBhc3N3b3Jk
    byte[]   credDecoded = Base64.getDecoder().decode(credEncoded);         //[B@7850a50e
    String   credString  = new String(credDecoded, StandardCharsets.UTF_8); //myuser:myuserpassword
    String[] credentials = credString.split(":", 2);                        //[myuser, myuserpassword]
    String   username    = credentials[0];                                  //myuser
    String   password    = credentials[1];                                  //myuserpassword

    //CREATE AUTHENTICATION OBJECT (with Entered Username & Password)
    Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);

    //GET    AUTHENTICATION OBJECT (with Authorities)
    authentication = authenticationManager.authenticate(authentication);

    //STORE AUTHENTICATION INTO CONTEXT (SESSION)
    SecurityContextHolder.getContext().setAuthentication(authentication);

    //FORWARD REQUEST
    filterchain.doFilter(request, response);

  }

}
