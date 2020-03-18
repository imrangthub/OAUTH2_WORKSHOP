package com.madbarsoft.util;

import java.util.List;
import java.util.Map;


public class Response {
	
	private boolean success = true;
	private boolean info = false;
	private boolean warning = false;
	private String message;
	private boolean valid = false;
	
	private    Long id;
	private   Map<String,Object> model;
	private    List items;
	private    Object obj;
	
	
	public Response(){}
	
	
	
	public Response(boolean success, boolean info, boolean warning, String message, boolean valid, Long id,
			Map<String, Object> model, List items, Object obj) {
		super();
		this.success = success;
		this.info = info;
		this.warning = warning;
		this.message = message;
		this.valid = valid;
		this.id = id;
		this.model = model;
		this.items = items;
		this.obj = obj;
	}
	public boolean isSuccess() {
		return success;
	}
	public void setSuccess(boolean success) {
		this.success = success;
	}
	public boolean isInfo() {
		return info;
	}
	public void setInfo(boolean info) {
		this.info = info;
	}
	public boolean isWarning() {
		return warning;
	}
	public void setWarning(boolean warning) {
		this.warning = warning;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public boolean isValid() {
		return valid;
	}
	public void setValid(boolean valid) {
		this.valid = valid;
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public Map<String, Object> getModel() {
		return model;
	}
	public void setModel(Map<String, Object> model) {
		this.model = model;
	}
	public List getItems() {
		return items;
	}
	public void setItems(List items) {
		this.items = items;
	}
	public Object getObj() {
		return obj;
	}
	public void setObj(Object obj) {
		this.obj = obj;
	}
	
	
	

}