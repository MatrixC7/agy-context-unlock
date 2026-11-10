# 技术报告：Google OAuth 原生通道上下文处理机制与实测数据

> **测试对象**：`antigravity-cli`（`/usr/bin/agy`）`1.5.1`，Linux x86-64，`SHA256: 72738cf0445918483956a5f0da33abdfcfb21a12dd9a421fd57d063782826669`。
> **测试通道**：Google 账号 OAuth 原生通道（`daily-cloudcode-pa.googleapis.com`）。
> **覆盖模型**：`Gemini 4 Argon (High)`、`Gemini 3.8 Flash (High)`。
> **通俗导读**：如需快速了解结论与配置方法，请参阅 [《原理与使用指南》](overview-and-guide.md)。

---

## 1. 术语与三种 Token 计量口径

在分析 `agy` 的上下文限制机制时，必须严格区分系统内同时存在的三种 Token 数值，避免跨口径混用：

| 口径分类 | 字段名称与协议位置 | 产生端与写入位置 | Argon 压缩转折点实测值 | 技术含义与边界 |
|---|---|---|---|---|
| **① 服务端宣告值与策略值** | `maxTokens` / `maxOutputTokens`<br>`CASCADE_USE_EXPERIMENT_CHECKPOINTER.max_token_limit` | Google Cloud Code PA 在 `v1internal:fetchAvailableModels` 响应中下发 | `maxTokens = 1,048,576`<br>`maxOutputTokens = 65,536`<br>`max_token_limit = 256,000` | 服务端宣告的模型容量与默认 Checkpoint 策略参数。`max_token_limit` 被客户端读取以构造本地预算，但不会随主生成请求回传服务端。 |
| **② 客户端本地诊断估算** | `gen_metadata` → `ChatStartMetadata.ContextWindowMetadata`<br>（`estimated_tokens_used` / `truncation_reason` / `max_context_tokens`） | `agy` 本地 `TrajectoryChatConverter`（`0x8255207..0x8255275`）构造并写入本地 SQLite | 压缩前末行：**`357,142`**（`reason=0`）<br>压缩后首行：**`14,947`**（`reason=2`）<br>`max_context_tokens = 256,000` | 客户端本地输出的上下文诊断估算值。**该结构体并非由服务端 SSE 返回**，且在英文填充文本下比服务端报告的 `promptTokenCount` 高出约 40%。 |
| **③ 服务端 SSE 报告用量** | `usageMetadata.promptTokenCount` | 服务端在 `v1internal:streamGenerateContent?alt=sse` 响应流末尾返回 | 压缩前主请求：**`248,479`**<br>独立摘要请求：**`256,515`**<br>压缩后主请求：**`10,750`** | 服务端对该次请求报告的输入 Token 用量。 |

### 1.1 `ContextWindowMetadata` 的本地构造证据（静态 ABI 与反汇编）

通过对 `/usr/bin/agy` 内置 Go 运行时类型元数据（`moduledata` 位于 `0xc8f6e40`）与 `chatconverters.(*TrajectoryChatConverter).TrajectoryToChatMessagesToTokenLimitOrStepIndex` 的反汇编分析，确认 SQLite `gen_metadata` 表中的 `ContextWindowMetadata` 完全由客户端本地构造：

| Go 运行时类型地址 | 结构体名称 | 字段名 | 内存偏移 | Protobuf 编号 | 本地写入指令地址 |
|---|---|---|---:|---:|---|
| `0xbd69b10` | `ContextWindowMetadata` | `EstimatedTokensUsed` | `+0x8` | `field 1` | `0x8255210` |
| `0xbd69b10` | `ContextWindowMetadata` | `TruncationReason` | `+0xc` | `field 2` | `0x8255217` |
| `0xbd69b10` | `ContextWindowMetadata` | `TokenBreakdown` | `+0x10` | `field 3` | — |
| `0xbd69b10` | `ContextWindowMetadata` | `MaxContextTokens` | `+0x18`（`*int32`） | `field 4` | `0x8255271`（读取传入的 token limit 参数） |
| `0xbeae870` | `ChatStartMetadata` | `ContextWindowMetadata` | `+0x38` | `field 10` | `0x8255275`（挂载至 `ChatStartMetadata`） |

与此同时，对服务端 `streamGenerateContent?alt=sse` 返回的所有 SSE 事件进行全深度字段名扫描，响应键集合仅为：
```text
candidates, candidatesTokenCount, content, finishReason, metadata, modelVersion,
parts, promptTokenCount, response, responseId, role, text, thoughtSignature,
thoughtsTokenCount, totalTokenCount, traceId, usageMetadata
```
响应流中不存在 `ContextWindowMetadata`、`estimated_tokens_used` 或 `truncation_reason` 字段。不过，`TrajectoryChatConverter` 内部包含 `modelReportedPrefixTokens`（`0x8255cc7` 调用，在 `0x8252949` 处读取历史 `GeneratorMetadataHeader.Usage`）与本地逐消息估算（`getNumTokensForChatMessage`）两条计算路径，这也是服务端下发策略中包含 `use_model_reported_token_count = true` 的原因。

---

## 2. 未修补状态下的一次对话完整生命周期

以下按执行顺序列出未修补版 `agy` 1.5.1 在单轮对话中的完整处理步骤及限制归属：

### 步骤 1：身份鉴权与模型清单拉取（`v1internal:fetchAvailableModels`）
- `agy` 启动后读取 `~/.gemini/antigravity-cli/settings.json` 与系统 Keyring 中的 OAuth 凭据，请求 `https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels`。
- 服务端返回的模型清單中，`Gemini 4 Argon`（High/Medium/Low）与 `Gemini 3.8 Flash`（High/Medium/Low）的关键参数一致：
  ```json
  {
    "id": "gemini-4-argon-high",
    "maxTokens": 1048576,
    "maxOutputTokens": 65536,
    "checkpoint_policy": {
      "enabled": true,
      "is_sync": true,
      "max_token_limit": 256000,
      "max_output_tokens": 16384,
      "max_overhead_ratio": 0.15,
      "token_threshold": 50000,
      "use_last_planner_model": true,
      "use_model_reported_token_count": true
    }
  }
  ```

### 步骤 2：本地构造 `CheckpointConfig` 与门禁检查
- **默认预算推导**：`utils.GetCheckpointConfig`（`0x7fb0ec0`）根据模型信息构造默认 `CheckpointConfig`，并在 `0x7fb0fe2` 处执行无符号钳位 `min(x, 256000)`，将结果写入 `CheckpointConfig.MaxTokenLimit`（偏移 `+0xc`，`0x7fb11b7`）。
- **用户覆盖检查**：`backend.(*ServerBackend).buildCascadeConfigInternal`（`0x9888380`）在 `0x9889063` 调用 `ServerBackend.ContextWindow`，其值由 `store.(*Manager).syncContextWindow` → `store.(*Store).ContextWindow`（`0x9c34b80`）提供：
  1. `Store.ContextWindow` 首先检查模型家族名是否位于硬编码单元素白名单 `["Gemini 4 Argon"]` 中；若未命中（如 `Gemini 3.8 Flash`），在 `0x9c34c49` 置 `%rax = -1` 并直接返回空串 `""`。
  2. 若命中白名单，在 `0x9c34c9a` 调用 `store.AutoCompactOverride`（`0x9c348e0`）读取环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE`。
  3. 当环境变量未设置时，执行流到达 `0x9c34ca5`，因内部接口 `*types.FeatureFlagReader` 断言分支未启用，跳过对 `store.(*Store).ContextWindowChoice`（`0x9c34b40`）的调用并直接返回空串 `""`。
- **GDB 动态验证**：在未修补二进制且未设置环境变量（即使 `settings.json` 中含有 `"contextWindow": "900K"`）的条件下，使用 GDB 在 `0x9889068`（`ContextWindow.MaxTokenLimit` 入口）、`0x988906d`（返回值检查）与 `0x98890fb`（函数返回前）截获寄存器，两个模型均实测输出：
  ```text
  CTXWINDOW_STRING_LEN=0
  CTXWINDOW_LIMIT=0
  CONFIG_RETURN_BEFORE_REQUEST=1
  ```
  证明未修补路径下 `settings.json` 中的 `"900K"` 未进入 `CheckpointConfig.MaxTokenLimit`，生效预算保持为默认的 `256,000`。

### 步骤 3：本地 Checkpoint 判断与独立摘要请求（压缩触发瞬间）
- 在发送本轮主请求前，`checkpoint.MaybeCreateCheckpoint`（`0x89d1ea0`）调用 `checkpoint.shouldCheckpoint`（`0x89d2360`）。
- `shouldCheckpoint` 在 `0x89d2426` 调用 `TrajectoryToChatMessages` 评估当前轨迹是否超出 `CheckpointConfig.MaxTokenLimit`。
- 当判定需要压缩时，客户端执行以下动作序列（TLS 抓包与 SQLite 交叉证实）：
  1. **发送独立摘要请求**：客户端先向 `v1internal:streamGenerateContent?alt=sse` 发送一个包含完整旧历史与延续摘要提示词（continuation summary prompt）的生成请求。
  2. **记录本地 `type=23` 步骤**：收到摘要响应后，`MaybeCreateCheckpoint` 在 `0x89d1fc5` 处创建 `step_type = 0x17`（23）的本地 Checkpoint 步骤并存入 SQLite `steps` 表。
  3. **发送瘦身后的主请求**：客户端使用浓缩后的历史替换原有数十条旧消息，在同一轮次内发出回答用户问题的主请求（请求体积由约 1.1 MB 骤降至约 45 KB，`request.contents` 条数由 55–58 条降至 1 条）。

### 步骤 4：HTTPS 主请求的线上结构（TLS 抓包审计）
- 通过 `mitmproxy` 对发往 `daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse` 的请求 JSON 做全深度、全数组递归键扫描：
  - **顶层键**：`project, requestId, request, model, userAgent, requestType`
  - **`request` 内部键**：`contents, generationConfig, includeThoughts, model, parts, systemInstruction, text, thinkingConfig, thinkingLevel, tools, functionDeclarations, parameters, properties, cascade_id, root_cascade_id, trajectory_id, last_step_index, labels, model_enum, used_non_gemini_model, used_claude, ...`
  - **配置键检索结果**：对 `checkpoint_config`、`checkpointConfig`、`cascade_config`、`cascadeConfig`、`max_token_limit`、`maxTokenLimit`、`context_window`、`contextWindow`、`maxContextTokens`、`autoCompact` 等命名变体进行全树搜索，**出现次数均为 0**。

---

## 3. 各阶段限制归属汇总表

| 阶段 | 涉及参数或行为 | 实际控制端 | 具体函数或协议位置 | 验证依据 |
|---|---|---|---|---|
| 模型容量宣告 | `maxTokens = 1,048,576`<br>`maxOutputTokens = 65,536` | Google 服务端宣告 | `fetchAvailableModels` | TLS 抓包响应 |
| 默认归档策略下发 | `max_token_limit = 256,000` | Google 服务端下发，`agy` 客户端消费 | `CASCADE_USE_EXPERIMENT_CHECKPOINTER` | TLS 抓包响应；SQLite `maxctx=256000` |
| 本地默认兜底钳位 | `min(x, 256000)` | `agy` 客户端 | `utils.GetCheckpointConfig`（`0x7fb0fe2`） | 反汇编 |
| 白名单与配置读取 | 单模型白名单与 `settings.json` 读取断路 | `agy` 客户端 | `store.(*Store).ContextWindow`（`0x9c34c49`, `0x9c34ca5`） | 反汇编；GDB `CTXWINDOW_LIMIT=0` |
| 自动压缩触发与执行 | 独立摘要请求 + `type=23` 步骤 + 历史替换 | `agy` 客户端 | `checkpoint.shouldCheckpoint` / `MaybeCreateCheckpoint` | TLS 抓包序列 + SQLite `steps` 表 |
| 诊断元数据落库 | `estimated_tokens_used` / `truncation_reason` / `max_context_tokens` | `agy` 客户端本地构造 | `TrajectoryToChatMessagesToTokenLimitOrStepIndex`（`0x8255207..0x8255275`） | 反汇编 + Go ABI 解码 + SSE 字段树扫描 |

---

## 4. 受控长会话实测数据

### 4.1 实验一：双模型逐轮 Wire `promptTokenCount` 与 SQLite `estimated_tokens_used` 完整对照
- **实验条件**：未修补 `/usr/bin/agy` 1.5.1，未设置 `AGY_CLI_AUTO_COMPACT_OVERRIDE`；每轮通过 `-p --conversation` 追加固定随机种子生成的英文词填充文本（前段每轮约 60 KB，DB 估算达 330K 后改为每轮约 30 KB 以提高转折点分辨率），同时全程捕获 TLS 请求字节数、消息条数与 SSE `usageMetadata.promptTokenCount`。

#### A. `Gemini 4 Argon (High)` 逐轮实测表（共 21 轮生成行 + 1 次独立摘要请求）

| 轮次 / DB 行号 | 请求类型 | 请求体字节数 | `contents` 条数 | HTTP 状态 | 服务端 SSE `promptTokenCount` | 本地 DB `estimated_tokens_used` | 本地 DB `reason` | 本地 DB `maxctx` |
|---|---|---|---|---:|---:|---:|---:|---:|
| row 0 | 主请求 | 32,887 | 1 | 200 | 7,486 | 10,707 | 0 | 256,000 |
| row 1 | 主请求 | 94,927 | 4 | 200 | 22,275 | 31,129 | 0 | 256,000 |
| row 2 | 主请求 | 156,469 | 7 | 200 | 35,855 | 51,454 | 0 | 256,000 |
| row 3 | 主请求 | 218,190 | 10 | 200 | 50,664 | 71,839 | 0 | 256,000 |
| row 4 | 主请求 | 279,881 | 13 | 200 | 64,128 | 92,212 | 0 | 256,000 |
| row 5 | 主请求 | 341,418 | 16 | 200 | 78,223 | 112,534 | 0 | 256,000 |
| row 6 | 主请求 | 403,116 | 19 | 200 | 92,408 | 132,910 | 0 | 256,000 |
| row 7 | 主请求 | 464,713 | 22 | 200 | 106,634 | 153,252 | 0 | 256,000 |
| row 8 | 主请求 | 526,226 | 25 | 200 | 121,305 | 173,566 | 0 | 256,000 |
| row 9 | 主请求 | 587,838 | 28 | 200 | 134,897 | 193,914 | 0 | 256,000 |
| row 10 | 主请求 | 649,372 | 31 | 200 | 149,056 | 214,235 | 0 | 256,000 |
| row 11 | 主请求 | 710,923 | 34 | 200 | 163,808 | 234,564 | 0 | 256,000 |
| row 12 | 主请求 | 772,597 | 37 | 200 | 177,860 | 254,926 | 0 | 256,000 |
| row 13 | 主请求 | 834,251 | 40 | 200 | 192,068 | 275,282 | 0 | 256,000 |
| row 14 | 主请求 | 895,812 | 43 | 200 | 206,296 | 295,608 | 0 | 256,000 |
| row 15 | 主请求 | 957,449 | 46 | 200 | 219,774 | 315,958 | 0 | 256,000 |
| row 16 | 主请求 | 1,019,109 | 49 | 200 | 233,945 | 336,315 | 0 | 256,000 |
| row 17 | 主请求（Needle 检索命中） | 1,050,772 | 52 | 200 | 241,193 | 346,714 | 0 | 256,000 |
| **row 18** | **压缩前最后大主请求** | **1,082,575** | **55** | **200** | **248,479** | **357,142** | **0** | **256,000** |
| *(Checkpoint)* | **客户端发起独立摘要请求** | **1,118,102** | **59** | **200** | **256,515** | *(写入 `type=23`, idx=58, 514,656 B)* | — | — |
| **row 19** | **压缩轮替换历史后的主请求** | **45,779** | **1** | **200** | **10,750** | **14,947** | **2** | **256,000** |
| row 20 | 下一轮常规主请求 | 107,387 | 4 | 200 | 24,978 | 35,285 | 0 | 256,000 |

#### B. `Gemini 3.8 Flash (High)` 与 `Gemini 4 Argon (High)` 关键转折点对比

| 观测指标 | `Gemini 4 Argon (High)` | `Gemini 3.8 Flash (High)` |
|---|---:|---:|
| 最后一次未压缩 DB 行 | row 18：`357,142`（`reason=0`） | row 19：`368,959`（`reason=0`） |
| 首个压缩后 DB 行 | row 19：`14,947`（`reason=2`） | row 20：`14,954`（`reason=2`） |
| 下一轮恢复增长 DB 行 | row 20：`35,285`（`reason=0`） | row 21：`35,514`（`reason=0`） |
| 最后大主请求字节数 / `contents` 条数 | `1,082,575` B / 55 条 | `1,122,308` B / 58 条 |
| **最后大主请求 SSE `promptTokenCount`** | **`248,479`** | **`248,371`** |
| 独立摘要请求字节数 / `contents` 条数 | `1,118,102` B / 59 条 | `1,158,324` B / 62 条 |
| **独立摘要请求 SSE `promptTokenCount`** | **`256,515`** | **`256,290`** |
| 压缩轮小主请求字节数 / SSE `promptTokenCount` | `45,779` B / `10,750` | `45,819` B / `10,652` |
| 本地 `type=23` Checkpoint 步骤索引 / 大小 | idx 58 / `514,656` B | idx 61 / `484,874` B |
| 第 17 轮 128-bit 随机事实（Needle）检索 | 精确命中（SSE `241,193` / DB `346,714`） | 精确命中（SSE `234,016` / DB `347,903`） |

**核心数据分析**：
1. 两个模型在压缩前最后一个大主请求的服务端报告用量（`promptTokenCount`）分别为 **`248,479`** 与 **`248,371`**，**仅相差 108 tokens**，而触发的独立摘要请求用量分别为 **`256,515`** 与 **`256,290`**——直接印证了底层正是围绕 `256,000` 预算阈值触发客户端压缩。
2. 相比之下，两者的本地 DB `estimated_tokens_used` 分别为 `357,142` 与 `368,959`（相差 `11,817`），证明本地 DB 估算值存在偏移，不能将 DB 估算值当作真实输入水位。

### 4.2 实验二：不同步长对照（恒定 60KB/轮 vs. 30KB/轮）
在恒定步长对照实验中（仅观察本地 DB `estimated_tokens_used`）：
- **60 KB/轮（约 20K DB tokens/轮）**：Argon 在 row 17（`356,214`）未压缩，row 18 压缩至 `14,787`（`reason=2`）；Flash 在 row 17（`356,555`）未压缩，row 18 压缩至 `15,139`（`reason=2`）。
- **30 KB/轮（约 10K DB tokens/轮）**：Argon 在 turn 34（`361,138`）未压缩，turn 35 压缩至 `14,702`（`reason=2`）。

### 4.3 实验三：解除 256K 预算限制（设置 `900,000` 上限）后的表现
当把客户端 `CheckpointConfig.MaxTokenLimit` 提升至 `900,000` 后：
- SQLite `gen_metadata` 中的 `max_context_tokens` 全程变为 **`900,000`**，`steps.user_input.user_config` 中明确记录 `checkpoint_config.max_token_limit = 900000`。
- `Gemini 4 Argon (High)` 实测连续运行至本地 DB 估算 **`840,522`** tokens，全程 `truncation_reason = 0`，未触发 `MAX_TOKEN_LIMIT` 自动压缩。
- `Gemini 3.8 Flash (High)`（应用补丁后）实测连续运行 42 轮至本地 DB 估算 **`869,213`** tokens，全程 `truncation_reason = 0`，未触发自动压缩。
