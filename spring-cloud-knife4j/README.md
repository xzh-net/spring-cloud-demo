# Gateway 聚合 Knife4j 文档

```bash
mvn clean compile
mvn clean package
```

```
spring-cloud-knife4j
├── gateway-server -- 网关 5001
└── user-service -- 注册到nacos的调用测试服务 5101

<spring-boot-dependencies.version>2.3.11.RELEASE</spring-boot-dependencies.version>
<spring-cloud-dependencies.version>Hoxton.SR9</spring-cloud-dependencies.version>
<spring-cloud-alibaba-dependencies.version>2.2.5.RELEASE</spring-cloud-alibaba-dependencies.version>
```

访问地址：http://127.0.0.1:5001/doc.html