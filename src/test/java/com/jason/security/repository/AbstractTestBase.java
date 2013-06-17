
package com.jason.security.repository;

import org.junit.Before;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
//import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;

@ContextConfiguration(locations = {"classpath:/META-INF/spring/application-root.xml",
		"classpath:/META-INF/spring/application-shiro.xml"})
public class AbstractTestBase extends AbstractTransactionalJUnit4SpringContextTests{

	protected static MockHttpServletRequest request;

	protected static MockHttpServletResponse response;

	@Before
	public void setUp() {
		initMockData();
	}
	protected void initMockData() {
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
	}
}
