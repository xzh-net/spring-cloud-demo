# Spring Cloud Dubbo RPC

```bash
mvn clean compile
mvn clean package
```

```
spring-cloud-dubbo
├── nacos-dubbo-provider -- 服务提供者7001
└── nacos-dubbo-consumer -- 服务消费者7101

<spring-boot-dependencies.version>2.6.3</spring-boot-dependencies.version>
<spring-cloud-dependencies.version>2021.0.1</spring-cloud-dependencies.version>
<spring-cloud-alibaba-dependencies.version>2021.0.1.0</spring-cloud-alibaba-dependencies.version>
```

从springboot 2.6.0以后，默认不允许循环依赖，解决办法：

```
spring:
  main:
    allow-circular-references: true
```

访问地址：http://127.0.0.1:7101/test?id=3

