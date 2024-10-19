package com.madbarsoft.role;

import java.util.List;

import org.hibernate.PersistentObjectException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class RolesService {

	@Autowired
	private RolesRepository repository;

	public List<RoleEntity> list() {
		return repository.list();
	}

	public List<RoleEntity> removeBooklist() {
		return repository.remove();
	}

	public void saveOrUpdate(RoleEntity obj) {
		try {
			if (obj.getId() == null) {
				repository.save(obj);
				return;
			}
			repository.update(obj);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new PersistentObjectException(ex.getCause().toString());
		}
	}

	public RoleEntity findById(Long id) {
		return repository.findById(id);
	}

	public RoleEntity findByIdAllItem(Long id) {
		return repository.findByIdAllItem(id);
	}

	public Boolean removeById(Long id) {
		if (findById(id) != null) {
			return repository.remove(findById(id));
		}
		return false;
	}

	public Boolean deleteById(Long id) {
		if (findByIdAllItem(id) != null) {
			return repository.delete(findByIdAllItem(id));
		}
		return false;
	}

}
