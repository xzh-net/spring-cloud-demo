# ZooKeeper 注册中心


```bash
mvn clean compile
mvn clean package
```

```
<spring-boot-dependencies.version>2.1.7.RELEASE</spring-boot-dependencies.version>
<spring-cloud.version>Greenwich.SR5</spring-cloud.version>
```

```
spring-cloud-zookeeper
├── zookeeper-ribbon-service -- 原生ribbon集成微服务调用示例 4001
└── zookeeper-user-service -- 用户基础服务CRUD 4101
```

访问地址：http://127.0.0.1:4001/user/1