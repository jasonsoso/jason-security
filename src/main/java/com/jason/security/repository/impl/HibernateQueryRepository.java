package com.jason.security.repository.impl;

import org.springframework.stereotype.Repository;

import com.jason.framework.orm.hibernate.HibernateRepositorySupport;
import com.jason.security.model.UserInfo;
import com.jason.security.repository.QueryRepository;

@Repository
public class HibernateQueryRepository extends HibernateRepositorySupport<Long, UserInfo> implements QueryRepository {

	@Override
	public UserInfo queryByName(String username) {
		return (UserInfo) super.queryUnique("from UserInfo where username=?", username);
	}
}
