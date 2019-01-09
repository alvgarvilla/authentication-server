package com.webberis.ms.authenticationserver.service.impl;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.webberis.ms.authenticationserver.entity.User;
import com.webberis.ms.authenticationserver.repository.UserRepository;
import com.webberis.ms.authenticationserver.service.UserService;

/**
 * UserServiceImpl - User Service Implementation
 *
 */

@Service
public class UserServiceImpl implements UserService {

	private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

	private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

	@Autowired
	UserRepository userRepository;

	@Override
	public void create(User user) {
		LOGGER.info("Creating new user. Username : " + user.getUsername());

		boolean existing = userRepository.existsById(user.getUsername());
		Assert.isTrue(!existing, "User already exists: " + user.getUsername());

		String hash = ENCODER.encode(user.getPassword());
		user.setPassword(hash);

		userRepository.save(user);
	}

	@Override
	public User loadUserByUsername(String username) throws UsernameNotFoundException {
		LOGGER.info("New loging request : " + username);

		User user = userRepository.findById(username)
				.orElseThrow(() -> new UsernameNotFoundException("Wrong credentials. Incorrect Username/Password"));

		return user;
	}

	@Override
	public void deleteAll() {
		userRepository.deleteAll();
	}

	@Override
	public List<User> retrieveAll() {
		LOGGER.info("Retrieving all Users.");

		List<User> userList = (List<User>) userRepository.findAll();

		return userList;
	}

	@Override
	public void createUsers(List<User> users) {

		users.forEach(user -> {
			LOGGER.info("Creating new user. Username : " + user.getUsername());

			Assert.isTrue(isValidPassword(user.getPassword()), "Invalid password: " + user.getPassword());

			String hash = ENCODER.encode(user.getPassword());
			user.setPassword(hash);
		});

		userRepository.saveAll(users);
	}

	private boolean isValidPassword(String password) {
		return !StringUtils.isEmpty(password) ? true : false;
	}
}
