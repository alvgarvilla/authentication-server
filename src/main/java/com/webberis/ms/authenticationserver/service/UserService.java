package com.webberis.ms.authenticationserver.service;

import java.util.List;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.webberis.ms.authenticationserver.entity.User;

public interface UserService extends UserDetailsService {
	
	void create(User user);

	void createUsers(List<User> users);

	void deleteAll();

	List<User> retrieveAll();

}
