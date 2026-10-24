# Plus 零库存发卡（plus_issue）

## 配置

### 站点设置 `plus_issue_config`

通过后台通用 settings API 写入：

```json
{
  "enabled": true,
  "base_url": "https://your-plus.example.com",
  "api_token": "<MALL_ISSUE_API_TOKEN>"
}
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

支付成功（含 BEpusdt 回调）→ 订单 `fulfilling` → 队列 `order:plus_issue` → 调用 plus `/api/v2/mall/cards/issue`（含 trade_id，plus 可复核 bepusdt）→ 写入 `fulfillments.payload` → 订单 `completed`。

发卡失败且可重试时由 asynq 重试；配置错误 / 缺支付凭证时停止重试，订单保持 `fulfilling` 供人工交付。

用户可在订单详情反复查看交付内容。
