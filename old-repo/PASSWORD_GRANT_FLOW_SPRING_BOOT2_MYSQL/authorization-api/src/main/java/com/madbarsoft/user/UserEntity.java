package com.madbarsoft.user;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import com.madbarsoft.role.RoleEntity;



@Entity
@Table(name = "users_tbl")
public class UserEntity  implements Serializable {


	private static final long serialVersionUID = 5167955767935040554L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;


	@Column(unique = true)
	private String username;

	private String password;


	private String fullName;


	private String email;
	

	@ManyToMany( fetch = FetchType.EAGER)
	@JoinTable(name = "users_roles_tbl", 
    joinColumns = {
	@JoinColumn(name = "USER_ID", referencedColumnName = "ID") },
    inverseJoinColumns = {
    @JoinColumn(name = "ROLE_ID", referencedColumnName = "ID") })
	private List<RoleEntity> roles = new ArrayList<RoleEntity>();


	public Long getId() {
		return id;
	}


	public void setId(Long id) {
		this.id = id;
	}


	public String getUsername() {
		return username;
	}


	public void setUsername(String username) {
		this.username = username;
	}


	public String getPassword() {
		return password;
	}


	public void setPassword(String password) {
		this.password = password;
	}


	public String getFullName() {
		return fullName;
	}


	public void setFullName(String fullName) {
		this.fullName = fullName;
	}


	public String getEmail() {
		return email;
	}


	public void setEmail(String email) {
		this.email = email;
	}


	public List<RoleEntity> getRoles() {
		return roles;
	}


	public void setRoles(List<RoleEntity> roles) {
		this.roles = roles;
	}


	@Override
	public String toString() {
		return "UserEntity [id=" + id + ", username=" + username + ", password=" + password + ", fullName=" + fullName
				+ ", email=" + email + ", roles=" + roles + "]";
	}
	
	
	
	

	

}
