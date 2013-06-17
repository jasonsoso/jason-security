package com.jason.security.repository;

import com.jason.security.model.UserInfo;


/**
 * 
 * @author Jason
 * @data 2013-6-17 下午10:16:42
 */
public interface QueryRepository {
	
	/**
	 * query by username
	 * @param username
	 * @return UserInfo
	 */
	UserInfo queryByName(String username);

}
