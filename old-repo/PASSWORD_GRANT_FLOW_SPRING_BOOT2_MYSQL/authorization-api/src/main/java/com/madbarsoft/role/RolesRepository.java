package com.madbarsoft.role;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class RolesRepository {

	@Autowired
	private EntityManager entityManager;

	public RoleEntity findById(Long id) {
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<RoleEntity> criteria = builder.createQuery(RoleEntity.class);
		Root<RoleEntity> root = criteria.from(RoleEntity.class);
		criteria.select(root).where(builder.equal(root.get("id"), id),
				builder.equal(root.get("isDeleted"), false));
		return entityManager.createQuery(criteria).getSingleResult();
	}

	public RoleEntity findByIdAllItem(Long id) {
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<RoleEntity> criteria = builder.createQuery(RoleEntity.class);
		Root<RoleEntity> root = criteria.from(RoleEntity.class);
		criteria.select(root).where(builder.equal(root.get("id"), id));
		return entityManager.createQuery(criteria).getSingleResult();
	}

	public List<RoleEntity> list() {
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<RoleEntity> criteria = builder.createQuery(RoleEntity.class);
		Root<RoleEntity> root = criteria.from(RoleEntity.class);
		criteria.select(root).where(builder.equal(root.get("isDeleted"), false));
		return entityManager.createQuery(criteria).getResultList();
	}

	public List<RoleEntity> remove() {
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<RoleEntity> criteria = builder.createQuery(RoleEntity.class);
		Root<RoleEntity> root = criteria.from(RoleEntity.class);
		criteria.select(root).where(builder.equal(root.get("isDeleted"), true));
		return entityManager.createQuery(criteria).getResultList();
	}

	public Boolean save(RoleEntity obj) {
		try {
			entityManager.persist(obj);
			return true;
		} catch (Exception ex) {
			ex.printStackTrace();
			return false;
		}
	}

	public Boolean update(RoleEntity obj) {
		try {
			entityManager.merge(obj);
			return true;
		} catch (Exception ex) {
			ex.printStackTrace();
			return false;
		}
	}

	public Boolean delete(RoleEntity obj) {
		try {
			entityManager.remove(obj);
			return true;
		} catch (Exception ex) {
			ex.printStackTrace();
			return false;
		}
	}

	public Boolean remove(RoleEntity obj) {
		try {
			obj.setDeleted(true);
			entityManager.merge(obj);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return false;
	}

}
