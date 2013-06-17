package com.jason.security.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.validation.constraints.Size;

import com.jason.framework.domain.AbstractDomainObject;
import com.jason.framework.util.ConvertUtils;


public class Role extends AbstractDomainObject  {
	private static final long serialVersionUID = 1L;

	@Size(min = 1, max = 32)
	private String name;
	
	@Size(min = 1, max = 32)
	private String showName;
	
	
	private Set<UserInfo> users = new HashSet<UserInfo>();

	private Set<Authority> authorities = new HashSet<Authority>();
	
	private Map<String, String> authorityMap = new HashMap<String, String>();
	
	
	public Set<UserInfo> getUsers() {
		if (null == users) {
			return Collections.emptySet();
		}
		return users;
	}

	public Role setUsers(Set<UserInfo> users) {
		this.users = users;
		return this;
	}

	public Set<Authority> getAuthorities() {
		if (null == authorities) {
			return Collections.emptySet();
		}
		return authorities;
	}

	public Role setAuthorities(Set<Authority> authorities) {
		this.authorities = authorities;
		return this;
	}
	
	public Map<String, String> getAuthorityMap() {
		if (null == authorityMap) {
			return Collections.emptyMap();
		}
		return authorityMap;
	}

	public Role setAuthorityMap(Map<String, String> authorityMap) {
		this.authorityMap = authorityMap;
		return this;
	}

	public Role fillupAuthorityMap() {
		Map<String, String> roleMap = new HashMap<String, String>();
		ConvertUtils.convertPropertyToMap(getAuthorities(), "id", "id", roleMap);
		return setAuthorityMap(roleMap);
	}


	public String getName() {
		return name;
	}

	public Role setName(String name) {
		this.name = name;
		return this;
	}

	public String getShowName() {
		return showName;
	}

	public Role setShowName(String showName) {
		this.showName = showName;
		return this;
	}

	public List<String> getAuthPermissions() {
		if (getAuthorities().isEmpty()) {
			return Collections.emptyList();
		}

		List<String> permissions = new ArrayList<String>();
		ConvertUtils.convertPropertyToList(getAuthorities(), "permission", ",", permissions);
		
		return permissions;

	}
	
	
}
