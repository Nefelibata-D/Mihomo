# 本 fork 的订阅配置

当前唯一的配置模板是 [weighted-sticky-subscription.yaml](weighted-sticky-subscription.yaml)。它是管理员为每个用户生成完整 Mihomo 订阅时的结构依据；其中所有 `.invalid` 地址、UUID、REALITY 公钥、短 ID、节点 ID 和示例域名都必须替换。模板本身不能连接真实节点，也不能作为生产订阅直接下发。

下发前需填入两端节点的地址、端口、用户 UUID、REALITY 参数，能稳定返回预期状态码的健康检查 URL，以及管理接口 HTTPS 地址和节点 ID。`control.uuid` 与该用户的管理身份对应。示例中美国节点也有 `node-ids` 映射：管理接口应对它返回 `normal`，不能因为美国节点不执行日本额度就省略映射，否则启用账户准入的组不会把它当作新绑定候选。按实际业务域名设置顶层 `site-blacklist` 和 `rules`；不要保留 `.invalid` 示例规则。填好后须用**当前源码构建**的 Mihomo 执行 `mihomo -t -f docs/extensions/weighted-sticky-subscription.yaml`，仓库里的旧二进制不能代表当前配置格式。

Mihomo 先按 `rules` 从上到下匹配目标，得到一个节点或代理组。只有规则选中 `type: load-balance` 且明确写了 `strategy: weighted-sticky` 的组，才运行加权黏性选路。单节点 `select` 组不做负载均衡；普通 `select`、其他负载均衡策略和直指节点的路由不读取本项目的网站黑名单。

顶层 `site-blacklist` 由所有启用 weighted-sticky 的组共享，按当前请求域名匹配。它只限制**没有有效缓存时的新建绑定**：有未列入黑名单的获准节点，就从这些节点中选；仅剩被列入黑名单的节点时仍可尝试。有效缓存先试原节点，明确 `disabled` 除外。组内权重只作用于首次抽选，后续失败由本次连接的有界重试轮转处理。

账户状态只来自管理接口；节点健康只来自代理组的官方 `url` / `expected-status` / `interval` 检查。健康结果不生成 `grace` 或 `disabled`。模板中的字段是本 fork 的扩展，上游 Mihomo 原生版本不能直接使用。
