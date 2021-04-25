package com.ivoronline.springboot_security_filter_authorizationheader.controllers;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {

  //========================================================================
  // HELLO
  //========================================================================
  @Secured("ROLE_USER")
  @RequestMapping("/Hello")
  public String hello() {
    return "Hello from Controller";
  }

}
