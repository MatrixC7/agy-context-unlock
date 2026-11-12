# 原理与使用指南：`antigravity-cli`（`agy`）的上下文压缩机制与解锁方案

> 本文档面向希望快速理解 `antigravity-cli`（`agy`）上下文限制成因、持久化配置逻辑以及解锁原理的用户与开发者。底层反汇编地址与逐轮抓包原始数据请参阅配套技术报告：
> - [《二进制补丁与脚本实现详解》（`binary-patch-internals.md`）](binary-patch-internals.md)
> - [《技术报告：Google OAuth 原生通道上下文机制与实测数据》（`mechanism-native-oauth.md`）](mechanism-native-oauth.md)
> - [《技术报告：企业网关与自定义模型上下文机制与实测数据》（`mechanism-enterprise-gateway.md`）](mechanism-enterprise-gateway.md)

---

## 1. 核心机制问答

### 1.1 长对话中的历史消息压缩，是由 Google 服务端执行的还是由 `agy` 客户端执行的？
**由本地 `agy` 客户端主动发起，而非服务端在主请求上强制截断。**

当对话累积到一定长度时，`agy` 客户端会在发送本轮问题前，先通过本地代码判断是否触及上下文预算上限（默认为 `256,000` tokens）。一旦触及上限，客户端会执行以下三步操作：
1. **发起独立摘要请求**：客户端向模型 API 发送一个独立的 `streamGenerateContent` 请求，要求模型将此前的对话历史浓缩为一段延续摘要（continuation summary）。
2. **写入本地 Checkpoint 记录**：客户端在本地 SQLite 会话数据库（`~/.gemini/antigravity-cli/conversations/<uuid>.db`）的 `steps` 表中写入一条 `type=23` 的 Checkpoint 步骤。
3. **替换历史并发送新请求**：客户端在本地将数十条旧消息替换为刚生成的摘要，再发出本轮真正的主请求（此时请求体积大幅缩小约 95%）。

在整个过程中，发往服务端的常规生成请求 JSON 中**不包含任何 `checkpoint_config` 或 `max_token_limit` 字段**。

---

### 1.2 既然默认预算是 `256,000`，为什么本地数据库显示到 `357,142`（甚至 `368,959`）才触发压缩？
**因为“本地数据库的诊断估算值”与“服务端报告的实际输入 Token 数”使用的是两套不同的计量口径。**

在 `agy` 的运行过程中，同时存在三种不同的 Token 数值：

| 计量口径 | 数据来源 | 压缩前最后一轮实测值（以 Argon 为例） | 真实含义 |
|---|---|---:|---|
| **① 模型宣告值与策略值** | 启动时请求 `fetchAvailableModels` 获得 | `maxTokens = 1,048,576`<br>`max_token_limit = 256,000` | 服务端宣告的模型最大输入容量（104.8 万）与默认建议归档阈值（25.6 万）。 |
| **② 客户端本地诊断估算**<br>（`estimated_tokens_used`） | `agy` 本地的 `TrajectoryChatConverter` 计算并写入 SQLite `gen_metadata` 表 | **`357,142`** | 客户端本地生成的诊断估算值。**该字段并非由服务端 SSE 返回，且比服务端计费 Token 数高出约 40%。** |
| **③ 服务端 SSE 报告用量**<br>（`usageMetadata.promptTokenCount`） | 服务端在每次流式响应末尾返回的实际用量统计 | **`248,479`** | 服务端对该次请求实际计算的输入 Token 数量。 |

将同一场对话跨过压缩点时的三轮数据并列对比，即可看清真实触发逻辑：

```text
[第 18 轮：压缩前最后一次正常主请求]
  客户端发送 JSON 体积 : 1,082,575 字节（含 55 条历史消息）
  ③ 服务端报告用量     : 248,479 tokens   <-- 尚未达到 256,000 预算线
  ② 本地数据库估算值   : 357,142 tokens（truncation_reason = 0，未压缩）

[第 19 轮开始前：继续累加将跨过 256,000 预算，客户端触发自动归档]
  客户端发送独立摘要请求: 1,118,102 字节（含 59 条消息，请求生成摘要）
  ③ 服务端报告用量     : 256,515 tokens   <-- 恰好跨过 256,000 预算线
  本地数据库记录动作   : 写入一条 type=23 的本地 Checkpoint 记录（约 514 KB）

[第 19 轮：客户端用摘要替换历史后，发送本轮主请求]
  客户端发送 JSON 体积 : 45,779 字节（旧历史已合并，contents 仅剩 1 条）
  ③ 服务端报告用量     : 10,750 tokens    <-- 上下文体积缩减约 95%
  ② 本地数据库估算值   : 14,947 tokens（truncation_reason = 2，标记为 MAX_TOKEN_LIMIT）
```

由此可见：**`256,000` 的本地预算一直在起作用**；当本地数据库显示 `357,142` 时，服务端口径下的真实输入量为 `248,479`，下一步即达到 `256,000` 触发线。

---

### 1.3 交互式 `/model` 菜单与 `settings.json` 的上下文配置是如何持久化的？为什么原版不生效？

在 `agy` 的代码设计中，用户通过交互式 `/model` 菜单切换上下文窗口（`256K` / `512K` / `900K`）**原本就是设计为自动持久化到 `~/.gemini/antigravity-cli/settings.json` 的**。完整链路分为“写入（保存）”和“读取（生效）”两半：

```text
【上半场：UI 切换并持久化写入磁盘（原版代码已实现）】
  用户在 /model 菜单按 [Tab] 切换 Context 档位（默认 / 256K / 512K / 900K）
       │
       ▼
  按 [Enter] 确认 ──► SelectorModel.selectRow ──► SelectorModel.windowToSave
       │
       ▼
  调用 store.(*Manager).SetContextWindow (0x9c34e00)
       │
       ▼
  调用 store.(*Manager).WriteCliSettings (0x9c26280)
       └──► 将 {"contextWindow": "900K"} 写入磁盘文件 ~/.gemini/antigravity-cli/settings.json

【下半场：从 settings.json 读取并写入压缩预算（原版被三处门禁阻断，由本项目补丁打通）】
  每次启动 agy 或切换模型 ──► 调用 store.(*Manager).syncContextWindow (0x9c34fa0)
       │
       ▼
  调用 store.(*Store).ContextWindow (0x9c34b80)
       ├──► 门禁 1：检查 "Gemini 4 Argon" 单模型白名单  ──► [补丁 store-gate 放行所有模型]
       ├──► 优先检查环境变量 AGY_CLI_AUTO_COMPACT_OVERRIDE（若设置则优先返回）
       └──► 门禁 2：未设环境变量时的回退分支原本被内部 Feature Flag 封死，直接返回 ""
            └──► [补丁 settings-window 将该分支接入 store.(*Store).ContextWindowChoice (0x9c34b40)]
            └──► 直接读取 ~/.gemini/antigravity-cli/settings.json 中的 "contextWindow": "900K"！
       │
       ▼
  调用 backend.(*ServerBackend).buildCascadeConfigInternal (0x9888380)
       ├──► ContextWindow.MaxTokenLimit() 将 "900K" 解析为整数 900000
       ├──► 门禁 3：检查 proto.Equal(model, selectedOverride) ──► [补丁 model-gate 改为无条件写入]
       └──► 将 900000 写入 CheckpointConfig.MaxTokenLimit (+0xc)！
```

简言之：
- 在**未修补的原版 `agy` 1.5.1** 中，不仅 `/model` 里的 `[Tab] Context` 按钮对绝大多数模型隐藏（被 `offersContextWindow` 门禁挡住），而且就算手动在 `settings.json` 里写上 `"contextWindow": "900K"`，读取函数 `Store.ContextWindow` 也会因为内部 Feature Flag 关闭而直接返回空字符串，导致配置形同虚设。
- 在**应用本项目的 4 个核心补丁（共 20 字节）**后，上述“UI 切换 → 写入 `settings.json` → 启动时自动从 `settings.json` 读取 → 写入 `CheckpointConfig.MaxTokenLimit`”形成完整闭环。用户既可以在 `/model` 菜单中按 `Tab` + `Enter` 永久切换档位，也可以直接编辑 `settings.json`，**日常使用完全无需手动指定环境变量**。

---

### 1.4 不同模型家族与思考强度的官方 `maxOutputTokens` 差异：为什么设为 `"900K"` 后 `Gemini 4 Carbon` 生效为 `786,432`？

在 `agy` 内部的 `GetCascadeConversationalConfigWithExperiment` 配置组装链路中，客户端写入的 `"900K"`（`900,000`）经合并后会执行 `utils.ClampCheckpointConfigForModelInfo` 模型物理上界检查：

$$\text{最终生效预算} = \min\big(\text{用户设定值},\ \text{MaxTokens} - \text{MaxOutputTokens}\big)$$

实测官方目录（`GetAvailableModels`）表明：**同一模型家族内部，Low / Medium / High 三种思考强度的 `maxOutputTokens` 完全相同**（思考强度仅改变独立的 `thinkingLevel = 1 / 2 / 3` 字段），但不同模型代际的单次最大输出预留存在三档差异：

| 原生通道模型家族（Low / Medium / High 同值） | 官方总窗口 `maxTokens` | 官方最大输出 `maxOutputTokens` | 物理输入上界 `maxTokens - maxOutputTokens` | 未设档位默认预算 | 设为 `"900K"` 后的生效预算 |
|---|---:|---:|---:|---:|---:|
| **Gemini 4 Argon / Gemini 3.8 Flash** | `1,048,576` (1 Mi) | **`65,536`** (64 Ki) | `983,040` | `256,000` | **`900,000`** *(注)* |
| **Claude Opus 5.5 / Claude Sonnet 5.5** | `1,000,000` (1M) | **`128,000`** (128K) | `872,000` | `840,000`（`claude-1m_840k`） | **`872,000`** |
| **Gemini 4 Carbon** | `1,048,576` (1 Mi) | **`262,144`** (256 Ki) | `786,432` | `256,000` | **`786,432`** |

> *注*：若需在 Argon / Flash 上进一步释放 `900,000` 至物理上界 `983,040` 之间的余量，可通过 `AGY_CLI_AUTO_COMPACT_OVERRIDE=983040` 指定，引擎同样会在安全上界内生效。对于单次最大输出扩展至 `262,144`（256 Ki）的 `Gemini 4 Carbon`，引擎自动将 `"900K"` 钳位在 `786,432` 是为了给单轮输出预留充足空间，不会触发内部校验错误。

---

## 2. 两条通道对比：Google OAuth 原生通道 vs. 企业网关通道

`agy` 支持通过 Google 账号 OAuth 登录直连官方通道，也支持通过环境变量（`GOOGLE_GEMINI_BASE_URL` 与 `GEMINI_API_KEY`）或 `customModelsConfig` 接入本地或企业内部的兼容 API 网关。两条通道的上下文机制对比如下：

| 对比维度 | Google OAuth 原生通道 | 企业网关 / 自定义模型通道 |
|---|---|---|
| **通信协议与端点** | HTTPS 访问 `daily-cloudcode-pa.googleapis.com/v1internal:*` | HTTP/HTTPS 访问网关 `/v1beta/models/*:streamGenerateContent` |
| **模型清单返回内容** | `fetchAvailableModels` 下发 `maxTokens=1,048,576` 及实验策略 `max_token_limit=256000` | `/v1beta/models` 仅返回模型名称与描述，不下发 `maxTokens` 与 Checkpoint 策略 |
| **默认 `256,000` 预算的来源** | 来自服务端下发的实验策略值 + 本地兜底 | 客户端将网关模型识别为 **Custom Model（自定义模型）**，执行本地默认推导并经 `min(x, 256000)`（`0x7fb0fe2`）钳位为 `256,000` |
| **请求体是否含上限配置** | 否（主请求无 `checkpoint_config` 字段） | 否（主请求仅含 `contents`、`tools`、`generationConfig`、`systemInstruction`） |
| **自动压缩执行方** | `agy` 客户端本地发起 | `agy` 客户端本地发起 |
| **未修补时的压缩点（DB 估算）** | Argon / Flash：约 **`356K–369K`**（SSE 约 `248K`） | Argon / Flash：**`355,610` / `355,586`**<br>DeepSeek V4.1 Flash：**`315,097`** |
| **修补后的持久化配置支持** | 直接读取 `settings.json` 的 `"900K"`（或 `/model` 切换） | 直接读取 `settings.json` 的 `"900K"`（或 `/model` 切换；亦可通过环境变量自定义整数上限） |

> **为什么企业网关下 Gemini 在约 `355K`（DB 估算）压缩，而 DeepSeek 在约 `315K` 压缩？**
> 因为两者的本地预算虽然同为 `256,000`，但不同模型对相同文本的分词（Tokenizer）密度与用量统计比例不同，映射到客户端本地诊断估算值 `estimated_tokens_used` 时便呈现出 `355K` 与 `315K` 的差异，而非网关设置了不同的硬上限。

---

## 3. 常见认知误区与客观边界说明

1. **误区：“抓包看到 `1.1 MB` 的主请求返回了 `HTTP 200`，说明已经实测跑通了 `1M`（100 万）tokens！”**
   - **客观事实**：请求体的**字节数（Bytes）不等于 Token 数**。实测 `1.08 MB`～`1.14 MB` 的 JSON 请求体，在服务端 SSE 报告的 `promptTokenCount` 中约为 **24.8 万 tokens**（对应本地数据库估算值约 `355K`–`357K`）。它证明了服务端与网关在 25 万 tokens 处不存在硬拒绝，但距离模型宣告的 `1,048,576` tokens 物理上限仍有约 4 倍差距。
2. **误区：“触发压缩的真实公式是 `1,048,576 × 0.35 ≈ 367,002`！”**
   - **客观事实**：`367K` 只是本地数据库诊断估算值（`estimated_tokens_used`）在特定英文随机词填充下的经验数值区间。由于该诊断值比服务端报告的 `promptTokenCount`（`248K` → `256.5K`）高出约 40%，刚好在数值上接近 `1,048,576` 的 35%，属于跨口径对比产生的数值巧合。底层代码实际传入的预算参数正是 `256,000`。
3. **误区：“只要数据库里 `truncation_reason = 0`，就证明服务端内部没有做任何截断！”**
   - **客观事实**：需分层表述证据边界：
     - **客户端发送层（已证实）**：通过消息对象哈希比对与 128-bit 随机事实“大海捞针（needle）”测试，已证实客户端在压缩前发出的 JSON 请求体完整保留了历史消息。
     - **服务端内部推理层（不可直接观测）**：由于外部无法获取上游云端推理引擎的内部日志，`HTTP 200` 与 `reason = 0`（仅代表客户端未标记本地压缩）不能作为云端内部零转换的绝对证明。
4. **误区：“将本地上限调至 `900K` 后，任何模型都能无条件跑到 `900K`！”**
   - **客观事实**：客户端补丁解除了 `agy` 本地的 256K 自动摘要锁。对于原生通道模型，引擎仍会按 `MaxTokens - MaxOutputTokens` 自动保护输出预留（例如 Argon / Flash 为 `900,000`，Claude 5.5 自动钳位至 `872,000`，预留 256 Ki 输出的 Gemini 4 Carbon 自动钳位至 `786,432`）；但在企业网关下调用未下发真实 `maxTokens` 且物理窗口较小（如 128K 或 256K）的第三方自定义模型时，若请求超过上游模型的真实物理上限，上游 API 将返回超限错误。此时可通过 `AGY_CLI_AUTO_COMPACT_OVERRIDE=<合适阈值>` 或 `/model` 里的 `256K`/`512K` 档位按需匹配模型容量。
