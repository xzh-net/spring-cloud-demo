# 统一授权认证中心

## 1. 项目结构

### 1.1 认证中心
oauth2-uaa-server

### 1.2 非前后端分离客户端

使用springSecurity来实现自动单点登录

oauth2-client-order 订单中心

oauth2-client-member 会员中心

### 1.3 前后端分离客户端
oauth2-web-portal 前后端分离的单点登录与单点登出

####  1.3.1 实现差异

跨域间的前后端分离项目也是基于共享统一授权服务(UAA)的cookie来实现单点登录的，但是与非前后分离不一样的是存在以下问题需要解决

- 没有过滤器/拦截器，需要在前端判断登录状态
- 需要自己实现oauth2的授权码模式交互逻辑
- 需要解决安全性问题，oauth2的clientSecret参数放在前端不安全

####  1.3.2 工作流程

 ![](assets/oauth_web.png)

## 2. 核心接口

### 2.1 密码模式（password）

用户密码帐号直接包含在请求上，通常需要开发环境在能掌控范围内

1. 请求地址

   http://localhost:8080/oauth/token?grant_type=password&username={username}&password={password}&account_type={account_type}

2. 请求方式
   POST
   
3. 请求头

   | 参数名        | 参数值                          | 是否必须 | 类型   | 说明                                                         |
   | :------------ | :------------------------------ | :------- | :----- | :----------------------------------------------------------- |
   | Authorization | Basic {clientId}:{clientSecret} | 是       | string | {clientId}:{clientSecret} 的值必需使用base64加密，clientId为应用id，clientSecret为应用密钥 |

   ![](assets/authorization_code3.png)
   ![](assets/authorization_code2.png)

4. 请求参数

   | 参数名       | 参数值   | 是否必须 | 类型   | 说明     |
   | :----------- | :------- | :------- | :----- | :------- |
   | grant_type   | password | 是       | string | 授权类型 |
   | username     |          | 是       | string | 用户名   |
   | password     |          | 是       | string | 密码     |
   | account_type |          | 否       | string | 用户类型 |

5. 返回示例

   ```
   正确示例
   {
       "access_token": "3d2609cb-1b02-473e-a02e-531172097ad4",
       "token_type": "bearer",
       "refresh_token": "f2720215-e60c-4a55-8854-dcd06e011a58",
       "expires_in": 6692,
       "scope": "all"
   }
   
   错误示例
   {
       "error": "invalid_grant",
       "error_description": "Bad credentials"
   }
   ```

### 2.2 授权码模式（authorization_code）

access_token 只能通过 authorization_code的方式获取真正的access_token

①获取授权码 ②根据授权码去获取真正的access_token

#### 2.2.1 获取code

1. 请求地址

   http://localhost:8080/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scope}&state={state}

2. 请求方式

   GET

3. 请求参数

   | 参数名        | 参数值 | 是否必须 | 类型   | 说明                                                         |
| :------------ | :----- | :------- | :----- | :----------------------------------------------------------- |
| client_id     |        | 是       | string | 应用id                                                       |
| redirect_uri  |        | 是       | string | 回跳地址(必需和应用配置里面的地址一致)                       |
| response_type | code   | 是       | string | 返回类型                                                     |
| scope         |        | 否       | string | 授权范围                                                     |
| state         |        | 否       | string | 表示客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值 |

4. 返回示例

   登录成功后跳转回调地址redirect_uri并带上code参数

   ![](assets/authorization_code1.png)

#### 2.2.2 通过code获取token

1. 请求地址

   http://localhost:8080/oauth/token?code={code}&grant_type=authorization_code&redirect_uri={redirect_uri}&scope={scope}

2. 请求方式

   POST
   
3. 请求头

   | 参数名        | 参数值                          | 是否必须 | 类型   | 说明                                                         |
   | :------------ | :------------------------------ | :------- | :----- | :----------------------------------------------------------- |
   | Authorization | Basic {clientId}:{clientSecret} | 是       | string | {clientId}:{clientSecret} 的值必需使用base64加密，clientId为应用id，clientSecret为应用密钥 |

   ![](assets/authorization_code3.png)
   ![](assets/authorization_code2.png)

4. 请求参数

   | 参数名       | 参数值             | 是否必须 | 类型   | 说明                       |
   | :----------- | :----------------- | :------- | :----- | :------------------------- |
   | grant_type   | authorization_code | 是       | string | 授权类型                   |
   | code         |                    | 是       | string | 第一步获取的授权码         |
   | redirect_uri |                    | 是       | string | 回调地址，必需与第一步一致 |
   | scope        |                    | 否       | string | 授权范围                   |


5. 返回示例

   ```
   正确示例
   {
       "access_token": "3d2609cb-1b02-473e-a02e-531172097ad4",
       "token_type": "bearer",
       "refresh_token": "f2720215-e60c-4a55-8854-dcd06e011a58",
       "expires_in": 7199,
       "scope": "all"
   }
   
   错误示例
   {
       "error": "invalid_grant",
       "error_description": "Invalid authorization code: pIVAiC"
   }
   ```

   



### 2.3 隐式授权模式（implicit）

撤销授权码，直接把access_token放到浏览器地址上，与授权码模式只是`response_type`不一样

1. 请求地址

   http://localhost:8080/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=token&scope={scope}


2. 请求方式

   GET

3. 请求参数

   | 参数名        | 参数值 | 是否必须 | 类型   | 说明     |
   | :------------ | :----- | :------- | :----- | :------- |
   | client_id     |        | 是       | string | 应用id   |
   | redirect_uri  |        | 是       | string | 回调地址 |
   | response_type | token  | 是       | string | 返回类型 |
   | scope         |        | 否       | string | 授权范围 |

    

4. 返回示例

   登录成功后跳转回调地址并带上token参数
   ![](assets/implicit.png)
   
   
### 2.4 客户端凭证模式（client_credentials）

1. 请求地址
   
   http://localhost:8080/oauth/token?grant_type=client_credentials
   
2. 请求方式
   GET

3. 请求头

   | 参数名        | 参数值                          | 是否必须 | 类型   | 说明                                                         |
   | :------------ | :------------------------------ | :------- | :----- | :----------------------------------------------------------- |
   | Authorization | Basic {clientId}:{clientSecret} | 是       | string | {clientId}:{clientSecret} 的值必需使用base64加密，clientId为应用id，clientSecret为应用密钥 |

   ![](assets/authorization_code3.png)
   ![](assets/authorization_code2.png)

4. 请求参数

   | 参数名     | 参数值             | 是否必须 | 类型   | 说明     |
   | :--------- | :----------------- | :------- | :----- | :------- |
   | grant_type | client_credentials | 是       | string | 授权类型 |

    

5. 返回示例

   ```
   正确示例
   {
       "access_token": "92a30ffd-16ab-4340-9f05-3fe2887fe9e1",
       "token_type": "bearer",
       "expires_in": 7199,
       "scope": "all"
   }
   
   错误示例
   {
       "error": "unsupported_grant_type",
       "error_description": "Unsupported grant type: client_credentials"
   }
   ```

   

### 2.5 刷新token

1. 请求地址
   
   http://localhost:8080/oauth/token?grant_type=refresh_token&refresh_token={refresh_token}
   
2. 请求方式
   POST

3. 请求头

   | 参数名        | 参数值                          | 是否必须 | 类型   | 说明                                                         |
   | :------------ | :------------------------------ | :------- | :----- | :----------------------------------------------------------- |
   | Authorization | Basic {clientId}:{clientSecret} | 是       | string | {clientId}:{clientSecret} 的值必需使用base64加密，clientId为应用id，clientSecret为应用密钥 |

   ![](assets/authorization_code3.png)
   ![](assets/authorization_code2.png)


4. 请求参数

   | 参数名        | 参数值        | 是否必须 | 类型   | 说明          |
   | :------------ | :------------ | :------- | :----- | :------------ |
   | grant_type    | refresh_token | 是       | string | 授权类型      |
   | refresh_token |               | 是       | string | 刷新token的值 |

5. 返回示例

   刷新token后access_token会改变，而且expires延长，refresh_token则不会改变
   
   ```
	{
       "access_token": "89e35d2a-847b-45d4-b04d-28dc536316e2",
       "token_type": "bearer",
       "refresh_token": "f2720215-e60c-4a55-8854-dcd06e011a58",
       "expires_in": 7199,
       "scope": "all"
   }
   ```
   
   


### 2.6 检查token有效性

1. 请求地址
   
   http://localhost:8080/oauth/check_token?token={access_token}
   
2. 请求方式
   POST

3. 请求头

   | 参数名        | 参数值                          | 是否必须 | 类型   | 说明                                                         |
   | :------------ | :------------------------------ | :------- | :----- | :----------------------------------------------------------- |
   | Authorization | Basic {clientId}:{clientSecret} | 是       | string | {clientId}:{clientSecret} 的值必需使用base64加密，clientId为应用id，clientSecret为应用密钥 |

   ![](assets/authorization_code3.png)
   ![](assets/authorization_code2.png)

4. 请求参数

   | 参数名 | 是否必须 | 类型   | 说明            |
   | :----- | :------- | :----- | :-------------- |
   | token  | 是       | string | 需要检查的token |

5. 返回示例

   ```
   {
       "exp": 1715361433,
       "user_name": "admin",
       "authorities": [
           "1",
           "2",
           "3"
       ],
       "client_id": "OrderManagement",
       "scope": [
           "all"
       ]
   }
   ```

   
### 2.7 账号登出

## 3. OAuth2标准接口

### 3.1 授权端点/oauth/authorize

在org.springframework.security.oauth2.provider.endpoint里的AuthorizationEndpoint，请求方式get和post均可

![](assets/authorize.png)

### 3.2 令牌端点/oauth/token

在org.springframework.security.oauth2.provider.endpoint里的TokenEndpoint，请求强制使用POST方式

![](assets/token.png)

### 3.3 确认授权提交端点/oauth/confirm_access

在org.springframework.security.oauth2.provider.endpoint里的WhitelabelApprovalEndpoint

![](assets/confirm_access.png)




如果想自定义授权跳转端点可以通过修改AuthorizationServerConfigurerAdapter里的AuthorizationServerEndpointsConfigurer配置实现，详见代码

![](assets/confirm_access_update.png)


### 3.4 授权服务错误端点/oauth/error

在org.springframework.security.oauth2.provider.endpoint里的WhitelabelErrorEndpoint

![](assets/error.png)

### 3.5 令牌解析端点/oauth/check_token

在org.springframework.security.oauth2.provider.endpoint里的CheckTokenEndpoint，请求方式GET和POST均可

![](assets/check_token.png)

### 3.6 获取密钥端点/oauth/token_key（如果使用JWT令牌的话）

在org.springframework.security.oauth2.provider.endpoint里的TokenKeyEndpoint

![](assets/token_key.png)

## 4. 授权服务配置

> 总体围绕 AuthorizationServerConfigurer的实现进行设计，我们需要自行实现其三个抽象方法，若需要启用Oauth2授权，则需要加入 @EnableAuthorizationServer

```java
// 配置客户端详情
public void configure(ClientDetailsServiceConfigurer clients) throws Exception {}
// 配置令牌端点的安全约束
public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {}
// 配置令牌访问端点和令牌服务
public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {}
```

### 4.1 ClientDetailsServiceConfigurer （配置客户端详情）

jdbc模式，见客户端表

```java
@Autowired
private DataSource dataSource;

@Override
public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.withClientDetails(jdbcClientDetailsService());
}

@Bean
public ClientDetailsService jdbcClientDetailsService() {
    // 存储client信息
    return new JdbcClientDetailsService(dataSource);
}
```

内存模式

```java
public void configure(ClientDetailsServiceConfigurer clients, Object clientDetailsService) throws Exception {
    clients.inMemory().withClient("client_1").secret(passwordEncoder().encode("123456"))
        .authorizedGrantTypes("password")
        .scopes("all");
}

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```
### 4.2 AuthorizationServerSecurityConfigurer（配置令牌端点的安全约束）

```java
/**
* 配置令牌端点的安全约束
*/
@Override
public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
    // 对获取Token的请求不再拦截
    oauthServer.tokenKeyAccess("permitAll()")
        // 验证获取Token的验证信息
        .checkTokenAccess("isAuthenticated()")
        .allowFormAuthenticationForClients();
}
```



- 允许表单验证
- 设置oauth_client_details加密方式
- 查询token信息管理
- 校验token是否可用

### 4.3 AuthorizationServerEndpointsConfigurer（配置令牌访问端点和令牌服务）

jdbc存储
```java
/**
* 配置令牌访问端点和令牌服务
*/
@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    //存储到数据库中
    endpoints.tokenStore(tokenStore())
        // 自定义授权跳转
        .pathMapping("/oauth/confirm_access", "/custom/confirm_access")
        // 注入WebSecurityConfig配置的bean
        .authenticationManager(authenticationManager);
}
```

jwt存储

```java
@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    // JwtToken存储
    endpoints.accessTokenConverter(jwtAccessTokenConverter());
    endpoints.tokenStore(jwtTokenStore())
        // 自定义授权跳转
        .pathMapping("/oauth/confirm_access", "/custom/confirm_access")
        // 注入WebSecurityConfig配置的bean
        .authenticationManager(authenticationManager);
}

@Bean
public JwtTokenStore jwtTokenStore() {
    return new JwtTokenStore(jwtAccessTokenConverter());
}

@Bean
public JwtAccessTokenConverter jwtAccessTokenConverter() {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    jwtAccessTokenConverter.setSigningKey("123");   //  Sets the JWT signing key
    return jwtAccessTokenConverter;
}
```

- authenticationManager 密码模式服务，如果不需要兼容 password 这种授权模式的话，可以不配置

- authorizationCodeServices 授权码模式服务，不配置的话，默认走内存模型

- tokenServices 令牌管理服务

  ```java
  @Autowired
  private ClientDetailsService clientDetailsService;//基于4.1选择的客户端模式会自动生成jdbc或内存的具体实现
  
  @Bean
  public AuthorizationServerTokenServices tokenServices() {
      DefaultTokenServices services = new DefaultTokenServices();
      services.setClientDetailsService(clientDetailsService);
      services.setSupportRefreshToken(true);//是否支持刷新令牌
      services.setTokenStore(tokenStore); //token的存放模式
      services.setAccessTokenValiditySeconds(7200); //控制超时时间
      services.setRefreshTokenValiditySeconds(259200);//控制刷新令牌的时间
      return services;
  }
  
  //token持久化方式
  //1、JdbcTokenStore           直接基于jdbc存贮
  //2、JwkTokenStore            直接拓展支持了JSON Web Key (JWK)、JSON Web Token (JWT)与JSON Web Signature (JWS)
  //3、InMemoryTokenStore       基于内存管理
  //4、RedisTokenStore          基于redis管理
  //5、JwtTokenStore            基于jwt存储，难以限定时间，需要自己让其变得无状态
  ```



## 5. 附带sql

### 5.1 oauth_client_details （授权码）

> 主要操作`oauth_client_details`表的类是`JdbcClientDetailsService.java`

```sql
DROP TABLE IF EXISTS `oauth_client_details`;

CREATE TABLE `oauth_client_details` (
  `client_id` varchar(255) NOT NULL COMMENT '客户端标识',
  `resource_ids` varchar(255) DEFAULT NULL COMMENT '接入资源列表',
  `client_secret` varchar(255) DEFAULT NULL COMMENT '客户端秘钥',
  `scope` varchar(255) DEFAULT NULL, 
  `authorized_grant_types` varchar(255) DEFAULT NULL,
  `web_server_redirect_uri` varchar(255) DEFAULT NULL,
  `authorities` varchar(255) DEFAULT NULL,
  `access_token_validity` int(11) DEFAULT NULL,
  `refresh_token_validity` int(11) DEFAULT NULL,
  `additional_information` longtext,
  `create_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `archived` tinyint(4) DEFAULT NULL,
  `trusted` tinyint(4) DEFAULT NULL,
  `autoapprove` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`client_id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC COMMENT='接入客户端信息';

```



### 5.2 oauth_code(支持授权码获取accessToken)

```sql
CREATE TABLE IF NOT EXISTS `oauth_code` (
  `code` VARCHAR(256) NULL DEFAULT NULL,
  `authentication` BLOB NULL DEFAULT NULL)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;
```



### 5.3 oauth_access_token（余下方式使用）

> 对`oauth_client_token`表的主要操作在`JdbcClientTokenServices.java`，实际上未使用到

```
CREATE TABLE IF NOT EXISTS `oauth_access_token` (
  `token_id` VARCHAR(256) NULL DEFAULT NULL,
  `token` BLOB NULL DEFAULT NULL,
  `authentication_id` VARCHAR(128) NOT NULL,
  `user_name` VARCHAR(256) NULL DEFAULT NULL,
  `client_id` VARCHAR(256) NULL DEFAULT NULL,
  `authentication` BLOB NULL DEFAULT NULL,
  `refresh_token` VARCHAR(256) NULL DEFAULT NULL,
  PRIMARY KEY (`authentication_id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;
```

### 5.4 oauth_refresh_token（余下方式使用）

```sql
CREATE TABLE IF NOT EXISTS `oauth_refresh_token` (
  `token_id` VARCHAR(256) NULL DEFAULT NULL,
  `token` BLOB NULL DEFAULT NULL,
  `authentication` BLOB NULL DEFAULT NULL)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;
```

## 6. 其他

> 编译中发现使用mvn package打包后的项目无法运行，提示容器中缺少bean，同样代码在idea中运行正常，怀疑是注入依赖的加载顺序有关系，使用@AutoConfigureAfter标签强制改变顺序。