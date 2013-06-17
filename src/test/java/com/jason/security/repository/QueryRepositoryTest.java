package com.jason.security.repository;


import java.util.Set;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.jason.security.model.UserInfo;

/**
 * @author Jason
 * @data 2013-6-17 下午09:46:02
 */
public class QueryRepositoryTest extends AbstractTestBase {

	@Autowired
	private QueryRepository queryRepository;
	
	@SuppressWarnings("unused")
	@Test
	public void testQueryByName(){
		UserInfo user = queryRepository.queryByName("jasonsoso");
		Set<String> roleNames = user.getRoleNames();
		Set<String> permissions = user.getPermissions();
		
		Assert.assertNotNull(user);
	}
	
}
