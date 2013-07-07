package com.jason.security.web.directive.freemarker;

import java.io.IOException;

import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;

import com.jagregory.shiro.freemarker.ShiroTags;

import freemarker.template.TemplateException;

/**
 * shiro-freemarker-tags 配置类
 * 
 * @author Jason
 * @data 2013-7-7 上午09:22:13
 */
public class FreeMarkerShiroDirectiveConfigurer extends FreeMarkerConfigurer {
	
	@Override
    public void afterPropertiesSet() throws IOException, TemplateException {
        super.afterPropertiesSet();
        this.getConfiguration().setSharedVariable("shiro", new ShiroTags());
    }
}
