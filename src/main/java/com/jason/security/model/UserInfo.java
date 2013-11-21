package com.jason.security.model;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;

import com.jason.framework.domain.IdDomainObject;
import com.jason.framework.util.ConvertUtils;


public class UserInfo extends IdDomainObject{
	private static final long serialVersionUID = 1L;

	@Size(min = 6, max = 20,message="用户名长度必须在6~20之间！")
	private String username;
	
	private String truename;
	
	@Size(min = 6, message="密码最少6个字符串！")
	private String password;
	
	//@Email
	@NotNull(message="邮箱不能为空！") 
	@Pattern(regexp = "[0-9a-z\\-\\_A-Z]+@[0-9a-z\\-\\_A-Z]+\\.[a-z]{2,}",message="Email格式不正确！")
	private String email;
	
	private String photo;
	
	private Date birth;

	//帐户非锁定
	private boolean accountNonLocked = true;
	
	//注册时间
	private Date createdAt;
	
	//最后修改时间
	private Date updatedAt;

	
	private Set<Role> roles = new HashSet<Role>();
	
	private Map<String, String> roleMap = new HashMap<String, String>();
	
	
	public UserInfo(){
	}
	public UserInfo(long id){
		this.id = id;
	}
	public UserInfo(String username){
		this.username = username;
	}

	@JsonIgnore
	public Set<Role> getRoles() {
		if (null == roles) {
			return Collections.emptySet();
		}
		return roles;
	}

	public String getRolesAsString() {
		return ConvertUtils.convertPropertyToString(getRoles(), "name", ",");
	}
	public Map<String, String> getRoleMap() {
		if (null == roleMap) {
			return Collections.emptyMap();
		}
		return roleMap;
	}
	public UserInfo setRoleMap(Map<String, String> roleMap) {
		this.roleMap = roleMap;
		return this;
	}

	public UserInfo fillupRoleMap() {
		Map<String, String> roleMap = new HashMap<String, String>();
		ConvertUtils.convertPropertyToMap(getRoles(), "id", "id", roleMap);
		return setRoleMap(roleMap);
	}

	public UserInfo setRoles(Set<Role> roles) {
		this.roles = roles;
		return this;
	}

	public Set<String> getAuthorityNames() {
		Set<String> authorityNames = new LinkedHashSet<String>();
		for (Role role : getRoles()) {
			for (Authority authority : role.getAuthorities()) {
				authorityNames.add(authority.getName());
			}
		}
		return authorityNames;
	}
	public Set<String> getRoleNames() {
		if (getRoles().isEmpty()) {
			return Collections.emptySet();
		}

		List<String> namesList = new LinkedList<String>();
		ConvertUtils.convertPropertyToList(getRoles(), "name", ",", namesList);
		return new HashSet<String>(namesList);
	}
	public Set<String> getPermissions() {
		if (getRoles().isEmpty()) {
			return Collections.emptySet();
		}

		Set<String> permissions = new HashSet<String>();
		for (Role role : getRoles()) {
			permissions.addAll(role.getAuthPermissions());
		}

		return permissions;
	}
	
	public UserInfo encodePassword(String encoder) {
		return setPassword(encoder);
	}
	
	
	public String getUsername() {
		return username;
	}

	public UserInfo setUsername(String userName) {
		this.username = userName;
		return this;
	}

	public String getTruename() {
		return truename;
	}

	public UserInfo setTruename(String trueName) {
		this.truename = trueName;
		return this;
	}

	public String getPassword() {
		return password;
	}

	public UserInfo setPassword(String password) {
		this.password = password;
		return this;
	}

	public String getEmail() {
		return email;
	}

	public UserInfo setEmail(String email) {
		this.email = email;
		return this;
	}
	
	public String getPhoto() {
		return photo;
	}

	public UserInfo setPhoto(String photo) {
		this.photo = photo;
		return this;
	}

	public Date getBirth() {
		return birth;
	}
	public UserInfo setBirth(Date birth) {
		this.birth = birth;
		return this;
	}
	
	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}

	public UserInfo setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
		return this;
	}
	public String getAccountNonLocked() {
		return isAccountNonLocked()?"正常":"冻结";
	}

	public Date getCreatedAt() {
		return createdAt;
	}

	public UserInfo setCreatedAt(Date createdAt) {
		this.createdAt = createdAt;
		return this;
	}

	public Date getUpdatedAt() {
		return updatedAt;
	}

	public UserInfo setUpdatedAt(Date updatedAt) {
		this.updatedAt = updatedAt;
		return this;
	}
	
	
}
