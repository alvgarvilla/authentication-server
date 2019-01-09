package com.webberis.ms.authenticationserver.repository;

import org.springframework.data.repository.CrudRepository;

import com.webberis.ms.authenticationserver.entity.User;

public interface UserRepository extends CrudRepository<User, String> {

}
