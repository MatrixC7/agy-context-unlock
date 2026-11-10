# 技术报告：企业网关与自定义模型上下文处理机制

> **测试对象**：`antigravity-cli`（`/usr/bin/agy`）`1.5.1`，Linux x86-64，`SHA256: 72738cf0445918483956a5f0da33abdfcfb21a12dd9a421fd57d063782826669`。
> **测试通道**：通过 `GOOGLE_GEMINI_BASE_URL` 与 `GEMINI_API_KEY`（或 `customModelsConfig`）接入的 `/v1beta` 兼容企业网关通道。
> **覆盖模型**：`<gateway>/gemini-4-argon-high`、`<gateway>/gemini-3.8-flash-high`、`<gateway>/deepseek-v4.1-flash-1017`。
> **通俗导读**：如需快速了解结论与配置方法，请参阅 [《原理与使用指南》](overview-and-guide.md)。

---

## 1. 核心结论

1. **企业网关本身未施加 256K 上下文硬限制；自动压缩依然由本地 `agy` 客户端发起。**
   发往网关 `/v1beta/models/*:streamGenerateContent?alt=sse` 的请求体中不包含任何 `checkpoint_config`、`max_token_limit` 或 `context_window` 字段。请求体增长至 `1.14 MB`（Gemini，对应本地 DB 估算 `355,610`）与 `1.02 MB`（DeepSeek，对应本地 DB 估算 `315,097`）时，网关均正常返回 `HTTP 200`。
2. **网关模型因被归类为 Custom Model（自定义模型），触发了客户端本地的 `min(x, 256000)` 默认钳位。**
   网关的 `/v1beta/models` 端点仅返回模型名称与描述，不返回 `maxTokens` 及 `CASCADE_USE_EXPERIMENT_CHECKPOINTER` 实验策略。`agy` 将其作为自定义模型处理，在 `utils.GetCheckpointConfig`（`0x7fb0fe2`）处将默认预算钳位为 `256,000`。
3. **未修补的原版 `agy` 在网关模式下会拦截所有自定义窗口配置，修补后则完全放行。**
   由于网关模型的显示名称（如 `"<gateway>/gemini-4-argon-high"`）不匹配 `store.(*Store).ContextWindow` 中的硬编码白名单 `"Gemini 4 Argon"`，原版 `agy` 下无论设置 `settings.json` 还是环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 均会被直接拦截。应用本项目的二进制补丁（`store-gate` + `settings-window` + `model-gate`）后，网关模型可直接通过 `settings.json`（或 `/model` 菜单、环境变量）将本地压缩预算提升至 `900,000`。

---

## 2. 企业网关通道的请求处理链路

### 步骤 1：模型发现与 Custom Model 构造
当使用环境变量指定网关地址启动，或在 `settings.json` 的 `customModelsConfig` 中配置自定义模型时：
```bash
GEMINI_API_KEY=<api-key> GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:<port> \
  agy --model '<gateway>/gemini-4-argon-high'
```
- 网关 `/v1beta/models` 接口返回的模型条目仅包含 `name`、`displayName`、`description` 与 `supportedGenerationMethods`，不含 `maxTokens`、`maxOutputTokens` 或 `modelExperiments`。
- 客户端通过 `backend.constructCustomModelInfo`（`0x987d920`）/ `constructFromCustomModelConfig`（`0x987d3a0`）将其组装为内部 `ModelInfo` 对象。

### 步骤 2：本地 `CheckpointConfig` 推导与白名单阻断
- 由于 `ModelInfo` 缺少服务端下发的 `modelExperiments` 策略，`utils.GetCheckpointConfig`（`0x7fb0ec0`）走默认推导分支，并在 `0x7fb0fe2` 处执行 `min(x, 256000)` 钳位，使 `CheckpointConfig.MaxTokenLimit` 默认固定为 `256,000`。
- 在未修补二进制中，`store.(*Store).ContextWindow`（`0x9c34b80`）检查白名单时因模型名称不等于 `"Gemini 4 Argon"` 而直接返回空字符串，导致用户设置的 `"900K"` 窗口或 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 无法进入 `CheckpointConfig`。

### 步骤 3：发送 `/v1beta` 生成请求（HTTP 反向代理抓包审计）
通过本地 `mitmdump` 反向代理对 `POST /v1beta/models/<model>:streamGenerateContent?alt=sse` 的请求体进行完整解析：
- **请求体顶层 JSON 键**：仅包含 `contents`、`generationConfig`、`systemInstruction`、`tools` 四项（标准 Gemini `/v1beta` 协议格式）。
- **配置字段检查**：全树扫描不存在任何 `checkpoint_config`、`max_token_limit` 或 `context_window` 字段。
- **大请求响应状态**：
  - `<gateway>/gemini-4-argon-high`：请求体从 `33 KB` 增长至 **`1,140,582` 字节（1.14 MB，34 条 `contents`）**，全程返回 `HTTP 200`。
  - `<gateway>/deepseek-v4.1-flash-1017`：请求体增长至 **`1,018,236` 字节（1.02 MB）**，全程返回 `HTTP 200`。

### 步骤 4：客户端本地触发 Checkpoint
与原生通道完全一致：当本地计算的上下文用量达到 `256,000` 预算时，`agy` 客户端本地的 `checkpoint.shouldCheckpoint` 触发，主动向网关发送独立的延续摘要请求，在本地 SQLite `steps` 表记录 `type=23` 的 Checkpoint 步骤，并将旧历史替换为摘要。

---

## 3. 实验数据：多模型默认压缩点与解锁验证

### 3.1 未修补状态下的三模型受控对比实验
在相同控制变量下（`1.5.1` 原版二进制，每轮通过 `-p --conversation` 追加 60 KB 英文填充文本，无环境变量覆盖），三个网关模型的实测压缩转折点如下：

| 网关模型标识 | 压缩前末行（DB `estimated_tokens_used`） | 压缩后首行（DB `estimated_tokens_used`） | 本地 DB `maxctx` | `user_config` 中是否含 `checkpoint_config` |
|---|---:|---:|---:|---|
| `<gateway>/gemini-4-argon-high` | **`355,610`**（`reason=0`） | **`14,807`**（`reason=2`） | `256,000` | 无 |
| `<gateway>/gemini-3.8-flash-high` | **`355,586`**（`reason=0`） | **`14,755`**（`reason=2`） | `256,000` | 无 |
| `<gateway>/deepseek-v4.1-flash-1017` | **`315,097`**（`reason=0`） | **`15,863`**（`reason=2`） | `256,000` | 无 |

**实验结论**：
1. 网关下的 Gemini 4 Argon（`355,610`）与 Gemini 3.8 Flash（`355,586`）的压缩点，同 Google OAuth 原生通道同步长下的压缩点（`356,214` / `356,555`）高度一致。
2. 网关下的 DeepSeek V4.1 Flash 在 DB 诊断估算达到 `315,097` 时触发压缩。由于三者的 `maxctx` 均为 `256,000` 且均由客户端发起 `type=23` Checkpoint，该差异源于不同模型的分词器（Tokenizer）及模型报告用量与本地诊断估算之间的换算比例差异，而非网关施加了不同的硬限制。

### 3.2 补丁解锁验证（`256,000` → `900,000`）
在网关模型 `<gateway>/gemini-4-argon-high` 上对比修补前后的配置写入结果：

| 测试条件 | SQLite `max_context_tokens` | `steps.user_input.user_config` 中的 `max_token_limit` | 结果说明 |
|---|---:|---:|---|
| 原版 `agy` + `AGY_CLI_AUTO_COMPACT_OVERRIDE=900000` | `256,000` | 未写入（空） | 被 `Store.ContextWindow` 白名单门禁拦截 |
| **修补版 `agy`** + `"900K"` 配置 | **`900,000`** | **`900,000`** | 白名单与配置读取打通，本地预算成功提升至 `900,000` |

> **关于长对话测试中的上游内容安全过滤（HTTP 400）说明**：
> 在对网关模型进行多轮随机词填充压测时，曾于第 2 轮（仅约 51K tokens，远低于默认已验证通过的 355K tokens）观察到上游返回 `Error 400: This request was blocked by Gemini's filters.`。该错误系随机生成的填充文本触发了上游 Gemini 的内容安全过滤器（Content Safety Filter），属于内容审查拦截而非上下文长度限制。网关与上游渠道在 400K–900K 极长输入下的实际接纳上限取决于具体网关实例的超时/请求体配置及上游模型配额。

---

## 4. 延伸分析：将网关接入其他 AI 客户端时的上下文边界

由于 256K 自动摘要限制完全位于 `agy` 客户端二进制内部，当把同一网关端点接入不包含 `agy` 本地 256K Checkpoint 逻辑的其他 AI 编程客户端时：
1. **`agy` 客户端层的 256K 自动压缩锁不复存在**。
2. 此时实际生效的上下文边界仅由以下三者共同决定：
   - **网关自身配置**：网关对单次 HTTP 请求体大小（如 `client_max_body_size`）、流式超时时间以及 `max_tokens` 转发规则的限制（实测默认已可正常转发 `1.14 MB` 请求体）。
   - **上游模型物理容量**：如 Gemini 3.8 / 4 的 `1,048,576` tokens（需预留 `maxOutputTokens` 输出空间）。
   - **客户端自身的上下文管理策略**。
