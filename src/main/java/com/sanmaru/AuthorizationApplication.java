package com.sanmaru;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthorizationApplication {

    final static Logger logger = LoggerFactory.getLogger(AuthorizationApplication.class);

    public static void main(String[] args){
        SpringApplication.run(AuthorizationApplication.class, args);
    }

}
