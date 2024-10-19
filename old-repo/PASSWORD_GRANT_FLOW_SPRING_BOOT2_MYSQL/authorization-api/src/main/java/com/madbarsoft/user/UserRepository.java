package com.madbarsoft.user;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.madbarsoft.base.BaseRepository;


@Repository
@Transactional
public class UserRepository extends BaseRepository {
	
	@Autowired
	private EntityManager entityManager;
	
	public UserEntity findById(Long id) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<UserEntity> criteria = builder.createQuery( UserEntity.class );
        Root<UserEntity> root = criteria.from(UserEntity.class);
        criteria.select(root).where(
                builder.equal(root.get("id"), id)
        );
        return entityManager.createQuery(criteria).getSingleResult();
    }
	
	
	public UserEntity findByUserName(String userName) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<UserEntity> criteria = builder.createQuery( UserEntity.class );
        Root<UserEntity> root = criteria.from(UserEntity.class);
        criteria.select(root).where(
                builder.equal(root.get("username"), userName)
        );
        return entityManager.createQuery(criteria).getSingleResult();
    }
	

    public List<UserEntity> list() {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<UserEntity> criteria = builder.createQuery( UserEntity.class );
        Root<UserEntity> root = criteria.from(UserEntity.class);
        return entityManager.createQuery(criteria).getResultList();
    }
   

    public Boolean save(UserEntity obj) {
        try{
            entityManager.persist(obj);
            return true;
        }catch (Exception ex){
            ex.printStackTrace();
            return false;
        }
    }

    public Boolean update(UserEntity obj){
        try{
            entityManager.merge(obj);
            return true;
        }catch (Exception ex){
            ex.printStackTrace();
            return false;
        }
    }

    public Boolean delete(UserEntity obj) {
        try{
            entityManager.remove(obj);
            return true;
        }catch (Exception ex){
            ex.printStackTrace();
            return false;
        }
    }
    


}
