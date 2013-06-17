## Introduction ##
JasonSecurity is a Shiro and [JasonFramewok](https://github.com/jasonsoso/jason-framework "jason-framework") based JavaEE application reference architecture.


## Clone and install ##
`git clone https://github.com/jasonsoso/jason-security.git`   
`cd jason-security`   
`mvn clean compile install`   
`mvn deploy   	 //Publish to nexus ,not the Required-election  `  


## Use  ##


- Add a dependency to pom.xml 

`
<dependency>   
  <groupId>com.jason</groupId>   
  <artifactId>securit</artifactId>   
  <version>1.0.0</version>   
</dependency>   
`

- Add the hibernate mapping files (Authority.hbm.xml、Role.hbm.xml、User.hbm.xml)

- Add application-shiro.xml

- See the demo [JasonAdmin](https://github.com/jasonsoso/jason-admin "jason-admin")
