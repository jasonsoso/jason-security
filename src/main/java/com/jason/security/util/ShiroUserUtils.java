package com.jason.security.util;

import org.apache.shiro.SecurityUtils;

import com.jason.security.realm.MyCasRealm.ShiroUser;

/**
 * 当前登陆者的信息辅助类
 * @author Jason
 * @date 2013-7-6 下午09:34:36
 */
public final class ShiroUserUtils {
	
	
	/**
	 * 判断当前是否登陆状态
	 * @return
	 */
	public static boolean isCurrentUser(){
		ShiroUser ShiroUser = getCurrentUser();
		if(null!=ShiroUser){
			return true;
		}else{
			return false;
		}
	}
	
	/**
	 * 查询当前登陆者信息
	 * @return ShiroUser
	 */
	public static ShiroUser getCurrentUser() {
		return  (ShiroUser) SecurityUtils.getSubject().getPrincipal();
	}
	/**
	 * 查询当前登陆者 用户名
	 * @return
	 */
	public static String getCurrentUserName() {
		return getCurrentUser().getUsername();
	}
	/**
	 * 查询当前登陆者 用户Id
	 * @return
	 */
	public static long getCurrentUserId() {
		return getCurrentUser().getId();
	}
	
	/**
	 * 查询当前登陆者 用户Id
	 * @return
	 */
	public static String getCurrentUserEmail() {
		return getCurrentUser().getEmail();
	}
	
	/**
	 * 查询当前登陆者 用户头像
	 * @return
	 */
	public static String getCurrentUserPhoto() {
		return getCurrentUser().getPhoto();
	}
	
}
