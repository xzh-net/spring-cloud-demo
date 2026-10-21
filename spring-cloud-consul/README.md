# Consul 注册与配置中心

```bash
mvn clean compile
mvn clean package
```

```
spring-cloud-consul
├── consul-config-client -- 配置中心客户端 6101 
├── consul-ribbon-service -- ribbon服务调用测试服务 6201
└── consul-user-service -- User对象CRUD接口的服务 6301

<spring-boot-dependencies.version>2.1.7.RELEASE</spring-boot-dependencies.version>
<spring-cloud.version>Greenwich.SR5</spring-cloud.version>
```

Consul下载地址：https://www.consul.io/downloads.html

```
consul --version
# 开发模式启动
consul agent -dev 
```

访问地址：http://localhost:8500

## 1. 用户基础服务接口（consul-user-service）



## 2. 配置中心客户端（consul-config-client）

- 在consul中添加配置存储的key为:
  ```
  config/consul-config-client:dev/data
  ```
- 在consul中添加配置存储的value为：  
  ```
  config:
    info: "config info for dev"
  ```
  
- 访问地址：http://localhost:7003/configInfo

## 3. ribbon服务（consul-ribbon-service）