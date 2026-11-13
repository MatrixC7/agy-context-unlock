# agy-context-unlock

**解除 `antigravity-cli`（`agy`）的 256K 本地上下文自动压缩限制，恢复 `/model` 交互菜单与 `settings.json` 的持久化上下文窗口配置（支持 Google OAuth 原生通道与企业网关自定义模型）。**

- **适用软件**：`antigravity-cli`（命令行工具 `/usr/bin/agy`，**非** Antigravity 桌面端 IDE；桌面端请参阅 [`antigravity-context-unlock`](https://github.com/MatrixC7/antigravity-context-unlock)）
- **已验证版本**：`1.5.7` Linux x86-64（`SHA256: 5df525a2d6908989c57b897723caea66e00d7c4d2e24411f91ad306989574642`），脚本通过动态解析 Go `pclntab` 符号表定位函数，不依赖固定文件偏移
- **历史版本**：仓库标签 **`v1.5.5`** 保存了 1.5.7 更新前的补丁线（在 1.5.1 锚点构建上验证，兼容 1.5.5）。需要修补 1.5.5 或在旧环境复现时，请 `git checkout v1.5.5`
- **支持通道与模型**：
  - **Google OAuth 原生通道**（`daily-cloudcode-pa.googleapis.com`）：`Gemini 4 Carbon`、`Gemini 4 Argon`、`Gemini 3.8 Flash`、`Claude 5.5` 等原生模型
  - **企业网关 / 自定义模型通道**（通过 `GOOGLE_GEMINI_BASE_URL` 或 `customModelsConfig` 接入的 `/v1beta` 兼容网关）：网关转发的 Gemini 系列与 DeepSeek 系列模型
- **运行依赖**：仅需 Python 3 标准库（零第三方依赖）
- **许可证**：[MIT License](LICENSE)

---

## 1. 背景与问题定义

尽管 Gemini 3.8 与 Gemini 4 系列模型宣告的最大输入容量为 **1,048,576 tokens**（`maxTokens = 1048576`），未修改的 `antigravity-cli`（`agy`）在实际使用中会在上下文达到 **256,000 tokens 预算**时提前触发自动压缩（Auto-Compaction / Checkpoint），将历史对话替换为一段摘要。在本地 SQLite 会话数据库的诊断字段 `estimated_tokens_used` 中，这一压缩点通常表现为 **356K–369K**（Gemini 系列）或 **315K**（DeepSeek 系列）。

结合对 `agy` 1.5.7 的静态反汇编与 1.5.1 的 TLS 流量审计记录，可以确认以下两项核心机制事实：

1. **自动压缩由 `agy` 客户端本地发起，而非上游模型 API 在主请求上的硬性截断。**
   `agy` 发往服务端的 `streamGenerateContent` 主请求 JSON 中不包含任何 `checkpoint_config`、`max_token_limit` 或 `context_window` 字段。客户端在每轮请求前通过本地 `checkpoint.shouldCheckpoint` 检查当前上下文是否达到 `CheckpointConfig.MaxTokenLimit`（默认 `256000`）。一旦触及预算线，客户端会主动发起一次独立的“生成延续摘要（continuation summary）”请求，在本地 SQLite `steps` 表中记录一条 `type=23` 的 Checkpoint 步骤，并用摘要替换旧历史消息。
2. **`agy` 二进制内部已完整实现 `/model` 菜单切换与 `settings.json` 持久化写入逻辑，但被三处内部门禁阻断：**
   - **UI 显示门禁（`offersContextWindow`）**：默认隐藏了绝大多数模型在 `/model` 菜单中的 `[Tab] Context (256K / 512K / 900K)` 切换项。
   - **单模型白名单门禁（`Store.ContextWindow`）**：在读取用户配置的上下文窗口前，先检查模型家族名是否匹配硬编码白名单（仅含 `"Gemini 4 Argon"` 一项）。`Gemini 3.8 Flash` 及所有网关自定义模型（如 `<gateway>/<provider>/...`）均在此处返回 `-1` 并直接退出。
   - **`settings.json` 读取分支死代码化（`ContextWindowChoice`）**：当用户在 `/model` 中切换窗口并回车时，`store.(*Manager).SetContextWindow` 会调用 `WriteCliSettings` 将 `"contextWindow": "900K"` 正常持久化写入 `~/.gemini/antigravity-cli/settings.json`。然而，在读取生效配置的函数 `Store.ContextWindow`（1.5.7：`0xa3fdee0`）中，原本用于调用 `Store.ContextWindowChoice`（`0xa3fdea0`，负责读取 `settings.json`）的分支被挂在一个面向内部环境的特性开关（`types.FeatureFlagReader`）之后。在公开版本中该开关恒为 `false`，导致持久化在 `settings.json` 中的 `"contextWindow"` 永远不会被读取生效。

---

## 2. 解决方案：20 字节二进制补丁与持久化闭环

`agy_context_unlock.py` 内置纯 Python 编写的 ELF64 与 Go 1.18+ 运行时符号表（`pclntab`）解析器。脚本不依赖脆弱的固定文件偏移，而是按符号名定位目标函数、校验函数体内的原始机器码签名后，精确修改 **4 处共 20 个字节**：

| 补丁标识 | 目标函数与虚拟地址（1.5.7） | 修改字节数 | 技术作用 |
|---|---|---:|---|
| **`ui-selector`** | `model.SelectorModel.offersContextWindow`<br>（`0xa6a03c0`） | **6 字节** | 将函数入口改为 `mov $1, %eax; ret`，使 `/model` 交互菜单中的 `[Tab] Context` 档位切换器对所有模型可见。 |
| **`store-gate`** | `store.(*Store).ContextWindow`<br>（`0xa3fdfa9`） | **5 字节** | 将白名单未命中的 `mov $-1, %rax` 替换为 `xor %rax, %rax` 与 `nop`，放行所有原生 Gemini 与网关自定义模型。 |
| **`settings-window`** | `store.(*Store).ContextWindow`<br>（`0xa3fe005` → `call 0xa3fdea0`） | **8 字节** | 将环境变量未设置时的回退分支直接接入 `store.(*Store).ContextWindowChoice`（`0xa3fdea0`），使其读取并校验 `~/.gemini/antigravity-cli/settings.json` 中的 `"contextWindow"` 字段。 |
| **`model-gate`** | `backend.(*ServerBackend).buildCascadeConfigInternal`<br>（`0xa08d0cb`） | **1 字节** | 将 `proto.Equal` 后的条件跳转 `jne`（`75`）改为无条件跳转 `jmp`（`eb`），确保非零窗口值无条件写入 `CheckpointConfig.MaxTokenLimit`（偏移 `+0xc`）。 |
| *(可选)* `default-clamp` | `utils.GetCheckpointConfig`<br>（`0x84f5e02`） | *(6 字节)* | 通过 `--with-default-clamp` 启用：将未设置任何窗口档位时的默认兜底钳位从 `256000` 提升至 `1048576`。 |

### 2.1 1.5.7 兼容性修复：`settings-window` 签名变化

从 `agy` 1.5.5 升级到 1.5.7 后，首次原地修补会报：

```text
[applying]
  [*] ui-selector      Context chip: offersContextWindow() -> true
  [*] store-gate       Context override: bypass the one-model whitelist gate
  [!] settings-window: settings-window: expected bytes not found in store.(*Store).ContextWindow
```

**根因**：1.5.7 调整了 `store.Store` 结构体布局，`featureProvider` 字段从 `+0xb8` 移到 `+0x58`。原 `settings-window` 签名覆盖了这条字段读取指令：

```text
1.5.5 (及更早): 48 8b 8c 24 08 01 00 00  48 8b 89 b8 00 00 00
                mov 0x108(%rsp),%rcx      mov 0xb8(%rcx),%rcx

1.5.7:          48 8b 8c 24 08 01 00 00  48 8b 49 58
                mov 0x108(%rsp),%rcx      mov 0x58(%rcx),%rcx
```

**修复**：仅更新这一处 14 字节匹配签名，补丁逻辑、调用目标与写入的 15 字节代码（含 `call ContextWindowChoice`）保持不变。`ContextWindowChoice` 本身在 1.5.7 中逻辑未变（仍读取 `cliSetting.contextWindow` 的 `+0x70/+0x78`），单模型白名单仍为 `["Gemini 4 Argon"]`，其余三个补丁签名也仍然精确匹配。

**安全性**：`cmd_patch` 先在内存中应用全部补丁，任一必选补丁失败即返回，**不会写入二进制**。因此上面这次失败不会留下“半修补”状态；本次实际检查也确认 `/usr/bin/agy` 仍是原版 SHA256 `5df525a2…574642`。

**1.5.7 实测对比**（未设置 `AGY_CLI_AUTO_COMPACT_OVERRIDE`，`settings.json` 为 `"contextWindow": "900K"`，GDB 在发出任何生成请求前终止）：

| 二进制 | `CTXWINDOW_STRING_LEN` | `CTXWINDOW_LIMIT` | `PROTO_EQUAL` | `WRITE_MAXTOKEN` |
|---|---:|---:|---:|---:|
| 1.5.7 原版 | `0` | `0` | *未触发* | *未写入* |
| 1.5.7 + 本仓库补丁 | `4`（`"900K"`） | `900000` | `1` | `900000` |

### 补丁生效后的配置持久化方式

打入上述 4 个核心补丁后，日常使用**无需包装启动器，也无需每次在终端指定环境变量**：

1. **通过交互式 `/model` 菜单切换（自动持久化）**：
   - 启动 `agy` 后输入 `/model` 打开模型选择器。
   - 按 **`Tab` 键**在 `默认`、`256K`、`512K`、`900K` 四档之间循环切换 `Context` 指示器。
   - 按 **`Enter` 键**确认。`agy` 会调用 `SetContextWindow` → `WriteCliSettings`，自动将 `"contextWindow": "900K"` 写入 `~/.gemini/antigravity-cli/settings.json` 并立即同步至当前会话；此后每次启动 `agy` 均会自动从 `settings.json` 读取该设置。
2. **直接编辑 `settings.json`（持久化）**：
   - 在 `~/.gemini/antigravity-cli/settings.json` 中设置 `"contextWindow": "900K"`（或 `"512K"` / `"256K"`），`agy` 在交互模式与 `-p` 非交互模式下启动时均会自动读取并生效。
3. **通过环境变量临时覆盖（备用最高优先级选项）**：
   - 环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 的检查顺序位于 `settings.json` 之前。当需要在特定脚本或非 900K 模型中临时指定任意整数阈值时，可使用 `AGY_CLI_AUTO_COMPACT_OVERRIDE=600000 agy ...` 覆盖默认配置。

---

## 3. 安装与部署指南

首先将本仓库克隆或放置于 `~/.local/share/agy-context-unlock`，并运行只读自检：

```bash
git clone https://github.com/MatrixC7/agy-context-unlock.git ~/.local/share/agy-context-unlock
cd ~/.local/share/agy-context-unlock

# 运行离线解析与补丁签名自检（纯只读，不修改任何文件）
python3 agy_context_unlock.py self-test --binary /usr/bin/agy
```

> 若系统仍是 `agy` 1.5.5（或更早），请先 `git checkout v1.5.5`，否则 1.5.7 的 `settings-window` 签名不会匹配。

根据系统环境选择以下任意一种部署方式：

### 方式 A（推荐）：原地修补 `/usr/bin/agy` + Pacman 自动更新 Hook

直接修补 `/usr/bin/agy` 后可直接使用原生 `agy` 命令。由于 `/usr/bin/agy` 属主为 `root:root`，普通用户权限下运行的 `agy` 内置后台更新器无法篡改该二进制文件。在 Arch Linux / EndeavourOS / CachyOS 等系统上，配合 Pacman `PostTransaction` Hook 可在每次软件包升级后自动重新应用补丁。

```bash
# 1. 原地修补 /usr/bin/agy（自动创建原版备份 /usr/bin/agy.agy-unlock-backup）
sudo python3 ~/.local/share/agy-context-unlock/agy_context_unlock.py patch \
  --binary /usr/bin/agy --in-place --yes --allow-system

# 2. 生成并安装 Pacman Hook（当 antigravity-cli 软件包安装或更新时自动重新修补）
#    Hook 中写入的必须是脚本的【绝对路径】。
#    注意：pacman hook 文件由 libalpm 直接解析并用 execv(3) 执行，不经过 shell，
#    因此开头的 ~ 不会被展开；请勿写成 ~/.local/...，否则 Hook 会在每次升级后静默失败。
#    pacman/99-agy-context-unlock.hook 是示例文件，其中的 /path/to/... 需按实际位置替换。
sudo mkdir -p /etc/pacman.d/hooks
sudo python3 ~/.local/share/agy-context-unlock/agy_context_unlock.py pacman-hook \
  --script-path ~/.local/share/agy-context-unlock/agy_context_unlock.py \
  --write /etc/pacman.d/hooks/99-agy-context-unlock.hook
```

> **关于 `~` 不展开的说明**：上面的 `--script-path ~/...` 由当前 shell 在调用 `python3` 前展开为绝对路径，因此没有问题；但 `pacman/99-agy-context-unlock.hook` 里的 `Exec` 行是由 libalpm 直接读取并 `execv(3)` 执行的，不经过任何 shell，`~` 会被当作字面字符传入，导致 Hook 静默失效。如需手写该文件，请填入完整绝对路径（例如 `/home/<you>/.local/share/agy-context-unlock/agy_context_unlock.py`）。

### 方式 B（免 root 权限）：在 `~/.local` 下安装独立只读副本

在不具备 root 权限或不希望修改系统目录的环境下，`install --patch` 可在 `~/.local/share/agy-context-unlock/agy` 生成修补后的二进制副本（自动设为 `0555` 只读权限以阻止内置自动更新器覆盖），并在 `~/.local/bin/agy-unlock` 生成启动脚本：

```bash
python3 ~/.local/share/agy-context-unlock/agy_context_unlock.py install \
  --patch --scope all --window 900000

export PATH="$HOME/.local/bin:$PATH"
agy-unlock --model "Gemini 3.8 Flash (High)"
```

---

## 4. 适用场景与各通道表现对比

| 接入通道 | 代表模型（Low / Medium / High 思考强度同值） | 未修补时的默认预算 / 压缩点 | 修补并启用 `"900K"` 后的生效表现 |
|---|---|---|---|
| **Google OAuth 原生通道** | `Gemini 4 Argon`<br>`Gemini 3.8 Flash` | `max_context_tokens = 256,000`<br>（SSE `promptTokenCount` 约 **248K**，本地 DB 估算约 **356K–369K**） | 生效预算提升至 **`900,000`**（物理输入上界 `1,048,576 - 65,536 = 983,040`；实测超 840K–869K 未触发自动压缩） |
| **Google OAuth 原生通道** | `Gemini 4 Carbon` | `max_context_tokens = 256,000` | 自动按物理输入上界钳位至 **`786,432`**（官方预留 `maxOutputTokens = 262,144`，经 `min(900000, 1048576 - 262144)` 安全生效） |
| **Google OAuth 原生通道** | `Claude Opus 5.5`<br>`Claude Sonnet 5.5` | CLI 默认命中 `claude-1m_840k` 变体为 **`840,000`** | 自动按物理输入上界提升并钳位至 **`872,000`**（`min(900000, 1000000 - 128000)`） |
| **企业网关 / 自定义模型通道** | `<gateway>/gemini-4-argon-high`<br>`<gateway>/gemini-3.8-flash-high` | 本地 SQLite `estimated_tokens_used` 显示约 **355K**（`maxctx = 256,000`） | 生效预算提升至 **`900,000`** |
| **企业网关 / 自定义模型通道** | `<gateway>/deepseek-v4.1-flash-1017` | 本地 SQLite `estimated_tokens_used` 显示约 **315K**（`maxctx = 256,000`） | 生效预算提升至 **`900,000`**（或通过 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 按上游模型实际容量设定） |

---

## 5. 验证方法

### 1. 静态补丁状态校验
```bash
python3 agy_context_unlock.py verify --binary /usr/bin/agy
```
确认 `ui-selector`、`store-gate`、`settings-window`、`model-gate` 四项均显示为 `PATCHED`。

### 2. GDB 零 Token 动态寄存器验证
`tools/gdb_verify.py` 通过 GDB 启动 `agy`，在配置构造函数 `backend.(*ServerBackend).buildCascadeConfigInternal` 返回前（1.5.7：`0xa08d11b`，尚未发起任何网络生成请求，消耗 0 Token）读取寄存器并终止进程。断点偏移由 `model-gate` 签名动态推导，不写死版本地址：

```bash
python3 tools/gdb_verify.py --binary /usr/bin/agy
```
当 `~/.gemini/antigravity-cli/settings.json` 中包含 `"contextWindow": "900K"` 时（无需设置任何环境变量），输出如下：
```text
== Gemini 4 Argon (High) ==
  CTXWINDOW_STRING_LEN=4
  CTXWINDOW_LIMIT=900000
  PROTO_EQUAL=1
  WRITE_MAXTOKEN=900000
  CONFIG_RETURN_BEFORE_REQUEST=1
  status=killed_before_config_return
```
未修补的 1.5.7 原版在同一条件下只输出 `CTXWINDOW_STRING_LEN=0` / `CTXWINDOW_LIMIT=0`，随后直接到达 `CONFIG_RETURN_BEFORE_REQUEST=1`。

### 3. 离线单元测试套件
```bash
python3 -m unittest discover -s tests -v
```

---

## 6. 仓库文档导航

本仓库提供由浅入深的完整文档体系，兼顾普通用户的快速理解与开发者的底层代码审计需求：

### 通俗导读与补丁实现原理
- **[《原理与使用指南（通俗导读）》（`docs/overview-and-guide.md`）](docs/overview-and-guide.md)**
  面向所有读者：用直观的对比和流程图解释 `agy` 上下文压缩的真实触发机制、三种不同的 Token 计数口径（宣告容量 vs. 本地 DB 诊断估算 vs. 服务端 SSE 报告用量）、`/model` 与 `settings.json` 的持久化闭环、以及原生通道与企业网关的异同。
- **[《二进制补丁与脚本实现详解》（`docs/binary-patch-internals.md`）](docs/binary-patch-internals.md)**
  面向开发者与逆向工程读者：深入解析 `agy_context_unlock.py` 的 ELF64 + Go `pclntab` 动态符号定位算法、4 个核心补丁（20 字节）与可选补丁的前后汇编指令对比、以及 1.5.7 的 `settings-window` 兼容性变更。

### 深度技术报告与实验证据
- **[《技术报告：Google OAuth 原生通道上下文机制与实测数据》（`docs/mechanism-native-oauth.md`）](docs/mechanism-native-oauth.md)**
  完整记录原生通道从启动鉴权、拉取策略、构造配置、发起独立摘要请求到本地 SQLite 落库的每一步代码路径、结构体偏移（`ContextWindowMetadata`）、TLS 抓包键树与逐轮 Token 实测数据（1.5.1 原始实验记录）。
- **[《技术报告：企业网关与自定义模型上下文机制与实测数据》（`docs/mechanism-enterprise-gateway.md`）](docs/mechanism-enterprise-gateway.md)**
  完整记录 `/v1beta` 企业网关与自定义模型通道的推导链路、本地反向代理抓包结果、Gemini 与 DeepSeek 多模型对比实验、以及网关接入其他客户端时的边界分析（1.5.1 原始实验记录）。

---

## 7. 安全机制与回滚说明

- **函数边界与唯一签名校验**：每个补丁仅在目标函数自身的 `[va, end)` 地址范围内检索原始机器码，且要求唯一精确匹配；若未来版本函数指令结构发生改变，脚本将安全中止，不会破坏二进制文件。1.5.7 的 `settings-window` 签名更新即遵循这一流程。
- **先内存应用、后原子写入**：`patch` 先对全部必选补丁做内存匹配与应用；任一失败立即返回，不写入文件，因此不会出现部分补丁落盘的状态。
- **原子替换与自动备份**：使用 `--in-place` 修补系统二进制时，脚本会自动备份原文件至 `/usr/bin/agy.agy-unlock-backup`，并通过同目录临时文件 + `fsync` + `os.replace` 完成原子写入。
- **一键还原原版二进制**：
  ```bash
  sudo python3 ~/.local/share/agy-context-unlock/agy_context_unlock.py restore --binary /usr/bin/agy
  sudo rm -f /etc/pacman.d/hooks/99-agy-context-unlock.hook
  ```
- **旧版本回退**：`git checkout v1.5.5` 可恢复 1.5.7 更新前的补丁脚本与文档。

---

## 8. 致谢与参考

本项目的机制分析、抓包取证与实验设计，参考了社区中关于 `antigravity-cli` 上下文行为的相关讨论与记录。感谢以下来源提供的线索与背景资料：

- **[google-antigravity/antigravity-cli Issue #1245](https://github.com/google-antigravity/antigravity-cli/issues/1245)**
  官方仓库中关于上下文窗口实际生效范围的 Issue 讨论，为本项目最初确认"256K 行为需要独立验证"提供了重要切入点。
- **[afengblog：Google Antigravity 256K 上下文窗口限制与无头模式政策变更](https://afengblog.com/blog/antigravity-256k-context-discrepancy.html)**
  对 `agy` 上下文容量与实际压缩点之间差异的整理，为本项目梳理"多种 Token 计数口径"提供了参考视角。
- **[linux.do 讨论帖 topic/3117832](https://linux.do/t/topic/3117832)**
  社区中对相关现象的实测交流与经验分享，为实验方向的取舍提供了帮助。

在机制梳理、脚本实现、文档撰写与实测验证中，主要工作由以下大语言模型完成：**Gemini 3.8 Flash**、**Gemini 4 Argon**、**DeepSeek V4.1 Flash 1017** 与 **GPT-6.1 Sol**；仓库维护者仅提供了需求设定、运行环境与实机测试条件等协助。谨致谢意。

---

## 9. 许可证

本项目基于 [MIT License](LICENSE) 发布。
