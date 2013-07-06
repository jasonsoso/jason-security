
package com.jason.security.realm;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasAuthenticationException;
import org.apache.shiro.cas.CasToken;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jason.security.model.UserInfo;
import com.jason.security.repository.QueryRepository;


/**
 * CAS+Shiro Realm
 * @author Jason
 * @date 2013-6-8 下午05:59:42
 */
public class MyCasRealm extends AuthorizingRealm {

    // default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
    public static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
    public static final String DEFAULT_VALIDATION_PROTOCOL = "CAS";
    
    private static Logger log = LoggerFactory.getLogger(MyCasRealm.class);

    private QueryRepository queryRepository;
    
    
    // this is the url of the CAS server (example : http://host:port/cas)
    private String casServerUrlPrefix;
    
    // this is the CAS service url of the application (example : http://host:port/mycontextpath/shiro-cas)
    private String casService;
    
    /* CAS protocol to use for ticket validation : CAS (default) or SAML :
       - CAS protocol can be used with CAS server version < 3.1 : in this case, no user attributes can be retrieved from the CAS ticket validation response (except if there are some customizations on CAS server side)
       - SAML protocol can be used with CAS server version >= 3.1 : in this case, user attributes can be extracted from the CAS ticket validation response
    */
    private String validationProtocol = DEFAULT_VALIDATION_PROTOCOL;
    
    // default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
    private String rememberMeAttributeName = DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME;
    
    // this class from the CAS client is used to validate a service ticket on CAS server
    private TicketValidator ticketValidator;
    
    
    public MyCasRealm() {
        setAuthenticationTokenClass(CasToken.class);
    }

    @Override
    protected void onInit() {
        super.onInit();
        ensureTicketValidator();
    }

    protected TicketValidator ensureTicketValidator() {
        if (this.ticketValidator == null) {
            this.ticketValidator = createTicketValidator();
        }
        return this.ticketValidator;
    }
    
    protected TicketValidator createTicketValidator() {
        String urlPrefix = getCasServerUrlPrefix();
        if ("saml".equalsIgnoreCase(getValidationProtocol())) {
            return new Saml11TicketValidator(urlPrefix);
        }
        return new Cas20ServiceTicketValidator(urlPrefix);
    }
    
    /**
     * 认证回调函数,登录时调用.
     * Authenticates a user and retrieves its information.
     * 
     * @param token the authentication token
     * @throws AuthenticationException if there is an error during authentication.
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        CasToken casToken = (CasToken) token;
        if (token == null) {
        	new CasAuthenticationException("Null casTokens are not allowed by this realm.");
            return null;
        }
        
        String ticket = (String)casToken.getCredentials();
        if (!StringUtils.hasText(ticket)) {
        	new CasAuthenticationException("Null tickets are not allowed by this realm.");
            return null;
        }
        
        TicketValidator ticketValidator = ensureTicketValidator();

        try {
            // contact CAS server to validate service ticket
            Assertion casAssertion = ticketValidator.validate(ticket, getCasService());
            // get principal, user id and attributes
            AttributePrincipal casPrincipal = casAssertion.getPrincipal();
            String userId = casPrincipal.getName();
            log.debug("Validate ticket : {} in CAS server : {} to retrieve user : {}", new Object[]{
                    ticket, getCasServerUrlPrefix(), userId
            });

            Map<String, Object> attributes = casPrincipal.getAttributes();
            // refresh authentication token (user id + remember me)
            casToken.setUserId(userId);
            String rememberMeAttributeName = getRememberMeAttributeName();
            String rememberMeStringValue = (String)attributes.get(rememberMeAttributeName);
            boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
            if (isRemembered) {
                casToken.setRememberMe(true);
            }
            // create simple authentication info
            /*List<Object> principals = CollectionUtils.asList(userId, attributes);
            PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());
            return new SimpleAuthenticationInfo(principalCollection, ticket);*/
            
            int id = Integer.parseInt((String)attributes.get("id"));
            String email = (String)attributes.get("email");
            String photo = (String)attributes.get("photo");
            return new SimpleAuthenticationInfo(new ShiroUser(id, userId, email,photo), ticket, userId);
            
        } catch (TicketValidationException e) { 
            throw new CasAuthenticationException("Unable to validate ticket [" + ticket + "]", e);
        }
    }
    
    /**
     *  授权查询回调函数, 进行鉴权但缓存中无用户的授权信息时调用.
     * Retrieves the AuthorizationInfo for the given principals (the CAS previously authenticated user : id + attributes).
     * 
     * @param principals the primary identifying principals of the AuthorizationInfo that should be retrieved.
     * @return the AuthorizationInfo associated with this principals.
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    	// null usernames are invalid
		if (principals == null) {
			throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
		}
		ShiroUser shiroUser = (ShiroUser) principals.getPrimaryPrincipal();
        try {

            UserInfo user = queryRepository.queryByName(shiroUser.getUsername());

            Set<String> roleNames = user.getRoleNames();
    		Set<String> permissions = user.getPermissions();
            
            // create simple authorization info
            SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo(roleNames);
            simpleAuthorizationInfo.setStringPermissions(permissions);
            return simpleAuthorizationInfo;
            
		} catch (Exception e) {
			throw translateAuthorizationException(e);
		}
        
    }
    
	/**
	 * 自定义Authentication对象，使得Subject除了携带用户的登录名外还可以携带更多信息.
	 * @author Jason
	 * @date 2013-7-6 下午09:53:03
	 */
	public static class ShiroUser implements Serializable {
		private static final long serialVersionUID = -1373760761780840081L;
		
		public int id;
		public String username;
		public String email;
		public String photo;

		public ShiroUser(int id,String username,String email,String photo) {
			this.id = id;
			this.username = username;
			this.email = email;
			this.photo = photo;
		}
		
		public int getId() {
			return id;
		}

		public String getUsername() {
			return username;
		}

		public String getEmail() {
			return email;
		}
		
		public String getPhoto() {
			return photo;
		}

		/**
		 * 本函数输出将作为默认的<shiro:principal/>输出.
		 */
		@Override
		public String toString() {
			return username;
		}

		/**
		 * 重载hashCode,只计算username;
		 */
		@Override
		public int hashCode() {
			return Objects.hashCode(username);
		}

		/**
		 * 重载equals,只计算username;
		 */
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			ShiroUser other = (ShiroUser) obj;
			if (username == null) {
				if (other.username != null)
					return false;
			} else if (!username.equals(other.username))
				return false;
			return true;
		}
	}
	
	private AuthorizationException translateAuthorizationException(Exception e) {
		if (e instanceof AuthorizationException) {
			return (AuthorizationException) e;
		}

		return new AuthorizationException(e);
	}

	
	
    public String getCasServerUrlPrefix() {
        return casServerUrlPrefix;
    }

    public void setCasServerUrlPrefix(String casServerUrlPrefix) {
        this.casServerUrlPrefix = casServerUrlPrefix;
    }

    public String getCasService() {
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }

    public String getValidationProtocol() {
        return validationProtocol;
    }

    public void setValidationProtocol(String validationProtocol) {
        this.validationProtocol = validationProtocol;
    }

    public String getRememberMeAttributeName() {
        return rememberMeAttributeName;
    }

    public void setRememberMeAttributeName(String rememberMeAttributeName) {
        this.rememberMeAttributeName = rememberMeAttributeName;
    }

	public QueryRepository getQueryRepository() {
		return queryRepository;
	}

	public void setQueryRepository(QueryRepository queryRepository) {
		this.queryRepository = queryRepository;
	}
    
}
