package com.madbarsoft.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class CustomGeneralExceptionHandler {
	private static final Logger logger = LoggerFactory.getLogger(CustomGeneralExceptionHandler.class);

	private String errorPage;

	public CustomGeneralExceptionHandler() {
	}

	public CustomGeneralExceptionHandler(String errorPage) {
		this.errorPage = errorPage;
	}

	public String getErrorPage() {
		return errorPage;
	}

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}


}
