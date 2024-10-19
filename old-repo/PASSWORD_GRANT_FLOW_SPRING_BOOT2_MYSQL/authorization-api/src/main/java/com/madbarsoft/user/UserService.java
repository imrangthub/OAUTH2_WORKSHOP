package com.madbarsoft.user;

import java.util.List;

import org.hibernate.PersistentObjectException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

	@Autowired
	private UserRepository repository;

    public List<UserEntity> list(){
        return repository.list();
    }


    public void saveOrUpdate(UserEntity obj){
        try{
            if(obj.getId()==null){
                repository.save(obj);
                return;
            }
            repository.update(obj);
        }catch (Exception ex){
            ex.printStackTrace();
            throw new PersistentObjectException(ex.getCause().toString());
        }
    }

    public UserEntity findById(Long id) {
        return repository.findById(id);
    }
    
    public UserEntity findByUserName(String userName) {
        return repository.findByUserName(userName);
    }

    
	

}
