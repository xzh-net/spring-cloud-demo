# Spring Cloud Alibaba 生态

```bash
mvn clean compile
mvn clean package
```

```
<spring-boot-dependencies.version>2.6.3</spring-boot-dependencies.version>
<spring-cloud-dependencies.version>2021.0.1</spring-cloud-dependencies.version>
<spring-cloud-alibaba-dependencies.version>2021.0.1.0</spring-cloud-alibaba-dependencies.version>
```

```
spring-cloud-alibaba
├── admin-server -- 微服务监控9101
├── config-client -- 配置中心客户端 9201
├── retrofit-service -- 整合retrofit 9301
├── ribbon-service -- 原生ribbon集成微服务调用示例 9401
├── sentinel-service -- 整合sentinel 9501
└── user-service  -- 注册到nacos的提供User对象CRUD接口的服务 9601
```

## 1. 微服务监控（admin-server）

- 访问地址：http://127.0.0.1:9000
- 客户端配置端点

```
management:
  endpoints:
    web:
      exposure:
        include: '*'
  endpoint:
    health:
      show-details: always
```

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

- 指定命名空间
```
cloud:
  nacos:
    discovery:
      namespace: 52c42c43-adae-4f52-91d0-7bdaf28d2ac9 
      server-addr: 172.17.17.137:8848
```

## 2. 配置中心客户端（config-client）

从springboot 2.4以后，默认不加载bootstrap配置文件，需要添加依赖

```
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-bootstrap</artifactId>
</dependency>
```

nacos配置添加`nacos-config-client-dev.yaml`为Data ID文件，默认组，配置格式YAML

```
config:
  info: "test"
```


访问地址：http://127.0.0.1:9001/configInfo

## 3. 整合sentinel（sentinel-service）

- 自定义限流
  - 按资源名，在本类中使用`blockHandler`指定限流逻辑（可以自定义消息，推荐）
  - 按url，默认限流逻辑，无须指定（提示信息不友好，不推荐使用）
  - 自定义限流处理，使用`blockHandlerClass`和`blockHandler`，指定全局限流逻辑类和方法（建议使用）
  
- 自定义降级
  - 按资源名，在本类中使用`handleFallback`指定降级逻辑，也叫兜底异常类
  - 兜底异常不需要配合sentinel-dashboard降级参数使用，即每次调用产生的异常都通过兜底类进行显示，当该资源设置了降级参数后，触发熔断指定时间窗内所有调用全部抛出`DegradeException`异常，此时调用不会进入逻辑方法中，实现了保护资源的目的，建议此处配合全局异常进行熔断信息的友好提示
  
- 整合Ribbon使用RestTemplate

  ```
  resttemplate:
    sentinel:
      enabled: true #打开@SentinelRestTemplate注解
  ```
  ```
  /**
   * 整合RestTemplate
   */
  @Configuration
  public class RibbonConfig {
  
      @Bean
      @LoadBalanced
      @SentinelRestTemplate(fallbackClass = ExceptionUtils.class,fallback = "handleFallback",blockHandler = "handleBlock" ,blockHandlerClass = ExceptionUtils.class)
      public RestTemplate restTemplate(){
          return new RestTemplate();
      }
  }
  ```
  ```
  package net.xzh.entities;
   
  import com.alibaba.cloud.sentinel.rest.SentinelClientHttpResponse;
  import com.alibaba.csp.sentinel.slots.block.BlockException;
  import org.springframework.http.HttpRequest;
  import org.springframework.http.client.ClientHttpRequestExecution;
   
  public class ExceptionUtils {
   
      /**
       * 静态方法，限流熔断业务逻辑
       * 返回值: SentinelClientHttpResponse
       * 参数 : request , byte[] , clientRquestExcetion , blockException
       */
      public static SentinelClientHttpResponse handleBlock(HttpRequest request, byte[] body, ClientHttpRequestExecution execution, BlockException ex) {
          return new SentinelClientHttpResponse("custom block info");
      }
   
      //异常降级业务逻辑
      public static SentinelClientHttpResponse handleFallback(HttpRequest request, byte[] body,
                                                              ClientHttpRequestExecution execution, BlockException ex) {
          return new SentinelClientHttpResponse("custom fallback info");
      }
  }
  ```
  
- 整合Feign

  ```
  feign:
    sentinel:
      enabled: true #打开sentinel对feign的支持
  ```
  ```
  /**
   * @Feign整合熔断
   */
  @FeignClient(value = "nacos-user-service",fallback = UserFallbackService.class)
  public interface UserService {
      @PostMapping("/user/create")
      CommonResult create(@RequestBody User user);
  }
  ```
  
- 使用Nacos存储规则

  sentinel-service修改application.yml配置文件，添加Nacos数据源配置

  ```
  spring:
    cloud:
      sentinel:
        datasource:
          ds1:
            nacos:
              server-addr: localhost:8848
              dataId: ${spring.application.name}-sentinel
              groupId: DEFAULT_GROUP
              data-type: json
              rule-type: flow
  ```

  nacos中添加json配置

  ```
  [
      {
          "resource": "/rateLimit/byUrl",
          "limitApp": "default",
          "grade": 1,
          "count": 1,
          "strategy": 0,
          "controlBehavior": 0,
          "clusterMode": false
      },
      {
          "resource": "byResource",
          "limitApp": "default",
          "grade": 1,
          "count": 5,
          "strategy": 0,
          "controlBehavior": 0,
          "clusterMode": false
      }
  ]
  ```

  ```
  resource：资源名称；
  limitApp：来源应用；
  grade：阈值类型，0表示线程数，1表示QPS；
  count：单机阈值；
  strategy：流控模式，0表示直接，1表示关联，2表示链路；
  controlBehavior：流控效果，0表示快速失败，1表示Warm Up，2表示排队等待；
  clusterMode：是否集群。
  ```

  > Spring Cloud Alibaba 官方文档：https://github.com/alibaba/spring-cloud-alibaba/wiki




## 4. 配合测试项目（user-service）

模拟基础用户的CRUD，以指定ip段注册


## 5. 整合Ribbon（ribbon-service）

原生ribbon集成微服务调用示例

新版本中取消了spring-cloud-starter-netflix-ribbon的依赖，手动引入，否则找不到服务

```yml
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-loadbalancer</artifactId>
</dependency>
```


## 6. 整合Retrofit（retrofit-service）

访问地址：http://127.0.0.1:9003/breaker/fallback/1

@RetrofitClient