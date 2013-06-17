package com.jason.security.realm;

import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import com.jason.security.model.UserInfo;
import com.jason.security.repository.QueryRepository;

/**
 * 
 * @author Jason
 *
 */
public class MyShiroRealm extends AuthorizingRealm {

	@Autowired
	private QueryRepository queryRepository;

	/**
	 * 授权查询回调函数, 进行鉴权但缓存中无用户的授权信息时调用.
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// null usernames are invalid
		if (principals == null) {
			throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
		}

		String username = (String) getAvailablePrincipal(principals);
		try {

			UserInfo user = queryRepository.queryByName(username);
			checkUser(user, username);

			Set<String> roleNames = user.getRoleNames();
			Set<String> permissions = user.getPermissions();
			SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
			info.setStringPermissions(permissions);
			return info;
		} catch (Exception e) {
			throw translateAuthorizationException(e);
		}
	}

	private AuthorizationException translateAuthorizationException(Exception e) {
		if (e instanceof AuthorizationException) {
			return (AuthorizationException) e;
		}

		return new AuthorizationException(e);
	}

	private void checkUser(UserInfo user, String username) {
		if (null == user) {
			throw new UnknownAccountException("No account found for user [" + username + "]");
		}

		if (!user.isAccountNonLocked()) {
			throw new LockedAccountException("Account found for user [" + username + "] is locked");
		}
	}

	private AuthenticationException translateAuthenticationException(Exception e) {
		if (e instanceof AuthenticationException) {
			return (AuthenticationException) e;
		}

		return new AuthenticationException(e);
	}

	
	/**
	 * 认证回调函数,登录时调用.
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		String username = upToken.getUsername();

		// Null username is invalid
		if (StringUtils.isBlank(username)) {
			throw new AccountException("Null usernames are not allowed by this realm.");
		}
		try {

			UserInfo user = queryRepository.queryByName(username);
			checkUser(user, username);

			return buildAuthenticationInfo(username, user.getPassword().toCharArray());
		} catch (Exception e) {
			throw translateAuthenticationException(e);
		}
	}

	protected AuthenticationInfo buildAuthenticationInfo(String username, char[] password) {
		return new SimpleAuthenticationInfo(username, password, getName());
	}
}
