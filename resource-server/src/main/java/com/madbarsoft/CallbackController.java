package com.madbarsoft;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CallbackController {

	Logger logger = LoggerFactory.getLogger(CallbackController.class);
	
    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code) {
    	logger.info( "AuthorizationCode: " + code);
        return "AuthorizationCode: " + code;
        
    }
}