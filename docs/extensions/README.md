# 本 fork 的路由与 weighted-sticky 配置

配置随管理员订阅下发。Mihomo 先按 `rules` 从上到下匹配目标，得到一个节点或代理组；只有规则选中 `type: load-balance` 且明确写了 `strategy: weighted-sticky` 的组，才运行本项目的加权黏性选路。普通 `select` 组、其他负载均衡策略和直指节点的路由不读取本项目的网站黑名单。

单节点目标可以让规则直接指向节点，或定义只含一个节点的普通 `select` 组。静态单节点组即使写了 `strategy: weighted-sticky` 也不会让整份配置加载失败：它按单节点直连处理，不做节点间负载均衡，但账户准入（`disabled`、`grace` 等）仍由该策略执行。动态 provider 暂时只剩一个节点时同样没有节点间选择；后续 provider 增加节点才有轮转。

网站黑名单位于**订阅顶层**，所有明确启用 `weighted-sticky` 的组共享同一份规则：

```yaml
site-blacklist:
  - proxy: 出口A
    domains: [login.example.test]
    domain-suffixes: [media.example.test]

proxy-groups:
  - name: 单节点出口
    type: select
    proxies: [出口B]
  - name: 多节点出口
    type: load-balance
    strategy: weighted-sticky
    proxies: [出口A, 出口B]
    weighted-sticky:
      weights: {出口A: 7, 出口B: 3}

rules:
  - DOMAIN-SUFFIX,single.example.test,单节点出口
  - MATCH,多节点出口
```

黑名单按请求域名匹配。它只限制**新建网站绑定**时的候选：有未列入黑名单的获准节点就优先从中选；只剩被列入的节点仍可尝试。有效缓存总是先试原节点，明确 `disabled` 除外。账户状态来自独立管理接口；节点健康来自官方健康检查。组内权重、缓存和有界轮转规则由 `adapter/outboundgroup/weighted_sticky_util/` 中的实现定义。

完整的本地隔离示例见 [基础示例](examples/weighted-sticky.yaml) 和 [含管理状态的示例](examples/weighted-sticky-resilience.yaml)。这些字段是本 fork 的扩展，不代表上游 Mihomo 原生支持。
