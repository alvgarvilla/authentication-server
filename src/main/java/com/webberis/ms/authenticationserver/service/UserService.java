package com.webberis.ms.authenticationserver.service;

import java.util.List;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
	
	void create(User user);

	void createUsers(List<User> users);

	void deleteAll();

	List<User> retrieveAll();

}
