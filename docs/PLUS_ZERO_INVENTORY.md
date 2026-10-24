# Plus 零库存发卡（plus_issue）

## 配置

### 站点设置 `plus_issue_config`

后台：系统设置 → 站点设置 → Plus 发卡。也可通过后台通用 settings API 写入：

```json
{
  "enabled": true,
  "base_url": "http://127.0.0.1:18081",
  "api_token": "<MALL_ISSUE_API_TOKEN>"
}
```

- `base_url` 是 plus 后端 Go 服务地址（同机部署填本机端口，不经过公网）。
- `api_token` 用 `app.secret_key` 做 AES-256-GCM 加密后存为 `api_token_enc`，数据库中不保存明文；
  读取接口只返回 `has_api_token`。保存时 `api_token` 留空表示保留原 Token。
- 修改 `app.secret_key` 后已保存的 Token 无法解密，需要重新填写。

### plus 服务端

```env
MALL_ISSUE_API_TOKEN=<与商城一致>
BEPUSDT_VERIFY_ENABLED=1
BEPUSDT_ALLOW_SKIP_VERIFY=0
```

发卡前会向 bepusdt 核对 `trade_id` 已支付，并把该 `trade_id` 绑定到唯一的商城订单号：

- 同一订单重试 → 幂等返回已发卡密
- 换一个订单号复用同一 `trade_id` → 拒绝（`TRADE_ALREADY_USED`）

因此不需要再维护卡种单价表。每个 plus_issue 订单目前只支持**一行商品**（一笔付款对应一张/一批同种卡）。

plus 的公网站点应屏蔽商城发卡接口，只允许本机调用：

```nginx
location ^~ /api/v2/mall/ { return 404; }
```

### 商品

- `fulfillment_type`: `plus_issue`
- 库存展示会按无限处理
- `plus_issue_config`（商品字段）:

```json
{
  "channel": "mapped_orchestrator",
  "service_type": "plus",
  "credit_quantity": 0
}
```

`channel` 仅支持 `mapped_orchestrator` / `local_pro`。

## 流程

支付成功（含 BEpusdt 回调）→ 订单 `fulfilling` → 队列 `order:plus_issue` → 调用 plus `/api/v2/mall/cards/issue`（含 trade_id，plus 复核 bepusdt 并把 trade_id 绑定到该订单）→ 写入 `fulfillments.payload` → 订单 `completed`。

发卡失败时由 asynq 重试，重试耗尽后订单保持 `fulfilling` 供人工交付；配置错误 / 缺支付凭证时直接停止重试。

用户可在订单详情反复查看交付内容。
