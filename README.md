# Spring Cloud

## 1. 服务注册与配置中心

- [ZooKeeper 注册中心](spring-cloud-zookeeper) — 使用 ZooKeeper 作为服务注册中心，含用户服务与 Ribbon 负载均衡调用示例

- [Consul 注册与配置中心](spring-cloud-consul) — 使用 Consul 同时作为服务注册中心和配置中心，含用户服务、配置客户端与 Ribbon 调用

- [Spring Cloud Netflix 全家桶](spring-cloud-netflix) — 基于 Eureka 注册中心，涵盖 Config 配置中心、Ribbon 负载均衡、Hystrix 熔断、Turbine 聚合监控、Feign 调用、Gateway/Zuul 双网关、Admin 监控

- [Spring Cloud Alibaba 生态](spring-cloud-alibaba) — 基于 Nacos 注册与配置中心，整合 Sentinel 限流熔断、Retrofit 声明式 HTTP 客户端、Ribbon 调用、Admin 监控

---

## 2. 服务治理与网关

- [Spring Cloud Dubbo RPC](spring-cloud-dubbo) — Nacos 作为注册中心，整合 Dubbo 实现 RPC 远程调用，含服务提供者与消费者

- [Gateway 聚合 Knife4j 文档](spring-cloud-knife4j) — Spring Cloud Gateway 统一聚合各微服务 Swagger/Knife4j 接口文档，访问 `/doc.html`

---

## 3. 安全认证

- [OAuth2 统一授权认证中心](spring-cloud-oauth2) — 基于 Spring Security OAuth2 的 UAA 认证中心，支持密码/授权码/隐式/客户端凭证 4 种模式，含非前后端分离 SSO 客户端（订单/会员）与前后端分离门户 SSO 接入
