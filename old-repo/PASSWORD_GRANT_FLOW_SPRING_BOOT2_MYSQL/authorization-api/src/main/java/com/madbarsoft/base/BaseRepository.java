package com.madbarsoft.base;

import javax.persistence.EntityManager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import javax.transaction.Transactional;
import java.util.List;



@Repository
@Transactional
public class BaseRepository {

	@Autowired
	private EntityManager entityManager;
	
	
    public <T>  T findById(long id, Class clzz) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<T> criteria = builder.createQuery(clzz);
        Root<T> root = criteria.from(clzz);
        criteria.select(root).where(
                builder.equal(root.get("id"), id)
               // builder.equal(root.get("isDeleted"), false)
        );
        return entityManager.createQuery(criteria).getSingleResult();
    }
	
	
    public <T> List<T> baseList(Class clzz) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<T> criteria = builder.createQuery(clzz);
        Root<T> root = criteria.from(clzz);
       // criteria.select(root).where(builder.equal(root.get("isDeleted"), false));
        return entityManager.createQuery(criteria).getResultList();
    }
	
	public <T> T baseSave(T obj) {
		try {
			entityManager.persist(obj);
			return obj;
		} catch (Exception e) {
			e.printStackTrace();
			// TODO: handle exception
			return obj;
		}
	}
	
	public <T> T baseUpdate(T obj) {
		try {
			entityManager.merge(obj);
			return obj;
		} catch (Exception e) {
			e.printStackTrace();
			// TODO: handle exception
			return obj;
		}
	}
	
	public <T> T baseSaveOrUpdate(T obj) {
		try {
			entityManager.merge(obj);
			return obj;
		} catch (Exception e) {
			e.printStackTrace();
			// TODO: handle exception
			return obj;
		}
	}
	
	public <T> boolean baseSoftDelete(T obj) {
		try {
			entityManager.merge(obj);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			// TODO: handle exception
			return false;
		}
	}
	
	public <T> boolean baseDelete(T obj) {
		try {
			entityManager.remove(obj);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			// TODO: handle exception
			return false;
		}
	}
	
	


}
