package com.madbarsoft.role;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import com.madbarsoft.user.UserEntity;

@Entity
@Table(name = "roles_tbl")
public class RoleEntity  implements Serializable {


	private static final long serialVersionUID = 7445912094988420567L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Integer id;

	
	private String name;

	private String description;
	
	
    @Column(columnDefinition = "boolean default false", nullable = false)
    private boolean isDeleted;


	public Integer getId() {
		return id;
	}


	public void setId(Integer id) {
		this.id = id;
	}


	public String getName() {
		return name;
	}


	public void setName(String name) {
		this.name = name;
	}


	public String getDescription() {
		return description;
	}


	public void setDescription(String description) {
		this.description = description;
	}


	public boolean isDeleted() {
		return isDeleted;
	}


	public void setDeleted(boolean isDeleted) {
		this.isDeleted = isDeleted;
	}


	@Override
	public String toString() {
		return "RoleEntity [id=" + id + ", name=" + name + ", description=" + description + ", isDeleted=" + isDeleted
				+ "]";
	}
    
    
    



	
}
