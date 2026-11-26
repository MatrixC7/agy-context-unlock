# agy-context-unlock

面向 **`antigravity-cli`（命令行工具 `/usr/bin/agy`，Linux x86-64）** 的零依赖本地上下文预算解锁工具：解除 `256K` 本地自动压缩限制，恢复 `/model` 交互菜单 `[Tab] Context` 档位切换与 `settings.json` 持久化闭环，并打通 `agy acp` 无头模式（如 T3 Code）的环境变量覆盖，同时支持 Google OAuth 原生通道与企业网关自定义模型。

---

## 核心特性

- **恢复 `/model` 与 `settings.json` 原生持久化闭环 + 打通 ACP 宿主环境变量覆盖**：按 Go 符号名动态定位目标函数，精确修改 **5 处核心位点（约 42 字节）**（`ui-selector`、`store-gate`、`settings-window`、`model-gate`、`acp-override`），恢复所有模型的 `[Tab] Context (256K / 512K / 900K)` 切换器与 `settings.json` 自动读取；同时让 `agy acp` 无头模式（如 T3 Code）在提供方环境变量中配置 `AGY_CLI_AUTO_COMPACT_OVERRIDE=900K`（或 `900000`）时直接生效。日常使用无需包装启动器（同时保留 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 作为最高优先级临时覆盖）。
- **跨版本自适应（已实机验证 `1.5.3` / `1.5.7` / `1.5.9` / `1.5.11` / `1.5.12` / `1.5.13` / `1.5.17` / `1.5.18`）**：`1.5.14` 起上游把上下文窗口解析函数由 `store.(*Store).ContextWindow` 改名为 `store.(*Store).AutoCompactWindow`（返回 `(窗口, 来源)` 两个字符串），脚本按“函数内是否含白名单门禁”自动选中真实函数，并按指令形状家族匹配 `settings.json` 回退分支，无需硬编码地址。
- **按模型家族自动遵循物理安全上界**：选择 `"900K"` 档位后，引擎仍会自动执行 `min(设定值, MaxTokens - MaxOutputTokens)` 保护输出预留：
  - `Gemini 4 Argon` / `Gemini 3.8 Flash`：**`900,000`**（物理上界 `983,040`，可经环境变量进一步释放）。
  - `Claude Opus 5.5` / `Claude Sonnet 5.5`：自动钳位至 **`872,000`**（`1,000,000 - 128,000`）。
  - `Gemini 4 Carbon`：自动钳位至 **`786,432`**（`1,048,576 - 262,144`）。
  - 企业网关自定义模型（Gemini / DeepSeek 等）：放行白名单门禁，直接支持 `settings.json` 或环境变量设定上限。
- **故障闭合、原子写入与备份安全机制**：内置纯 Python 标准库 ELF64 + Go 1.18+ `pclntab` 解析器，先在内存中匹配并预演全部必选补丁，任一失败即中止且不写盘；跨软件包升级原地修补时自动将旧备份轮换为 `.agy-unlock-backup.<旧SHA前8位>`，防止 `restore` 误降级；而在已修补的同一版本上增量叠加新补丁时，通过内存重放哈希校验原地保留原有的干净原版备份。
- **零外部依赖，职责独立**：仅需 Python 3 标准库；针对命令行版 `/usr/bin/agy`，与桌面端工具及多账号切号工具职责正交、互不冲突。

---

## 版本要求与兼容性

- **当前 `main` 分支适用范围**：`antigravity-cli >= 1.5.3`（Linux x86-64）。已在 `1.5.3` / `1.5.7` / `1.5.9` / `1.5.11` / `1.5.12` / `1.5.13` / `1.5.17` / `1.5.18` 八个构建上实机验证（`sha256` 前 16 位记录于脚本 `KNOWN_BUILDS`，命中即无需 `--allow-unknown`）。
  - **两种函数形态**：`≤ 1.5.13` 的解析函数为 `store.(*Store).ContextWindow`（返回 `string`）；`≥ 1.5.14` 改名为 `store.(*Store).AutoCompactWindow`（返回 `(window, source)` 共 4 个字），而 `ContextWindow` 退化为 `0x40` 字节的尾调用包装。脚本按“哪个符号的函数体内含白名单门禁”自动选择，不写死符号名。
  - **`settings.json` 回退分支按指令家族匹配**：`mov disp(%rsp),%reg` + `mov 0x58(%reg),%reg` 的寻址形式（`disp32`/`rcx` 或 `disp8`/`rdx`）随版本变化，脚本内置 3 种通配布局并按返回值个数（2 或 4）决定是否补零 `%rcx`/`%rdi`。
  - **未来版本**：若上游再次改动结构体偏移或符号名，脚本仍会以退出码 `3` 安全中止且不写入任何字节；此时先跑 `locate` 定位失配项。
- **实机兼容性判定**：可先运行只读 `locate --binary /usr/bin/agy` 确认 5 处必选补丁均显示 `patchable` 或 `already patched`；同时 `locate` 会打印每处补丁实际命中的函数名（如 `store.(*Store).AutoCompactWindow +0x12b`），便于快速核对版本形态。
- **适用对象与运行环境**：仅面向命令行工具 `/usr/bin/agy`（**非** Antigravity 桌面端 IDE）；仅需 Python 3 标准库，零第三方依赖。

### 版本段 × 实测状态矩阵

| `agy` 版本段 | 解析函数形态 | `settings-window` 指令布局 | 已实测构建 | 状态 |
|---|---|---|---|---|
| `1.5.1`–`1.5.5` | `store.(*Store).ContextWindow`（2 字返回） | **A1** `mov 0x108(%rsp),%rcx` + `mov 0xb8(%rcx),%rcx` | `1.5.3` | 可修补（`main` 实测 `1.5.3` 通过）；`1.5.1`/`1.5.2` 无可用样本，建议用 `v1.5.5` 标签 |
| `1.5.6`–`1.5.13` | `store.(*Store).ContextWindow`（2 字返回） | **A2** `mov 0x108(%rsp),%rcx` + `mov 0x58(%rcx),%rcx` | `1.5.7` / `1.5.9` / `1.5.11` / `1.5.12` / `1.5.13` | 全部实测通过 |
| `1.5.14`–`1.5.18+` | `store.(*Store).AutoCompactWindow`（4 字返回） | **B** `mov 0x70(%rsp),%rdx` + `mov 0x58(%rdx),%rdx` | `1.5.17` / `1.5.18` | 全部实测通过 |

- 三段布局在同一份 `main` 中共存，脚本按“哪个候选符号的函数体内含白名单门禁 + 哪种通配布局唯一命中”自动选择，无需按版本切换分支。
- 未实测的同段版本（如 `1.5.6` / `1.5.8` / `1.5.10` / `1.5.14`–`1.5.16`）指令形态一致，预期可直接修补；`locate` 会打印实际命中的函数与偏移，便于确认。
- 若某个版本出现 `acp-override NOT FOUND`（旧版 `buildCascadeConfigInternal` 内没有 `call ServerBackend.ContextWindow`），可用 `--patches ui-selector,store-gate,settings-window,model-gate` 只打 4 个核心补丁，交互式 `settings.json` 闭环不受影响。

### Tag 约定

本仓库的 tag 表示**该补丁线已验证到的上游版本上限**（tag 之间不构成互斥区间）：

| Tag | 含义 |
|---|---|
| `v1.5.5` | 1.5.7 之前的补丁线：`1.5.1`–`1.5.5`，不含 `acp-override` |
| `v1.5.18` | 当前 `main` 补丁线：已验证到 `1.5.18`（覆盖 `1.5.3`–`1.5.18` 三段布局） |

升级到新的上游版本并通过 `locate` + `patch` + `self-test` + GDB 验证后，在对应提交上追加一个同名 tag 即可（例如上游发布 `1.5.19` 并验证通过后打 `v1.5.19`），无需新建分支。

---

## 快速开始

```bash
git clone https://github.com/MatrixC7/agy-context-unlock.git ~/agy-context-unlock
cd ~/agy-context-unlock

# 1. 只读检查目标函数与 5 处必选（共 6 处）补丁位点（不修改任何文件）
python3 agy_context_unlock.py locate --binary /usr/bin/agy

# 2. 原地修补 /usr/bin/agy（自动创建/轮换原版备份；已收录构建无需 --allow-unknown）
sudo python3 ~/agy-context-unlock/agy_context_unlock.py patch \
  --binary /usr/bin/agy --in-place --yes --allow-system --allow-unknown

# 3. 校验 5 处必选补丁状态（确认输出 verified: required patches are present）
python3 ~/agy-context-unlock/agy_context_unlock.py verify --binary /usr/bin/agy
```

> [!IMPORTANT]
> **修补完成后启用高预算窗口**：
> - **交互式 CLI（`agy`）**：启动 `agy` 后输入 `/model`，按 `Tab` 键将 `Context` 切至 `900K`（或 `512K`）并按 `Enter` 确认，即可自动写入 `~/.gemini/antigravity-cli/settings.json` 并持久生效；亦可直接在该配置文件中设置 `"contextWindow": "900K"`。
> - **ACP 无头模式（如 T3 Code）**：`agy acp` 不读取交互式 `settings.json`，在宿主对应提供方环境变量（例如 T3 Code 的「设置 → 智能体提供方 → Antigravity → 环境 → 变量」）中添加 `AGY_CLI_AUTO_COMPACT_OVERRIDE=900K`（或 `900000`，注意 `K` 须大写）后**新开会话**（或重启宿主服务以重建 `agy acp` 子进程）即可生效；未设置该变量时保持原厂默认行为。

> [!WARNING]
> **不要直接运行“可写位置上的已修补副本”**：`agy` 自带后台自动更新器，在检测到新版本时会**覆盖同路径的二进制文件**（实测把 `/tmp` 下的已修补副本替换成了新版本，导致补丁静默失效）。安全做法只有两种：
> 1. 原地修补 `root:root` 拥有的 `/usr/bin/agy`（普通用户运行的更新器无法改写它）；
> 2. 使用 `install --patch`（安装后自动 `chmod 0555`）或自行 `chmod 555` 锁定副本，并在运行时设置 `AGY_CLI_DISABLE_AUTO_UPDATE=1`。

---

## 日常升级与卸载还原

系统升级 `antigravity-cli` 后，重新执行原地修补命令即可（脚本会自动轮换旧版备份，避免误降级）：

```bash
# 软件包升级后重新修补
sudo python3 ~/agy-context-unlock/agy_context_unlock.py patch \
  --binary /usr/bin/agy --in-place --yes --allow-system --allow-unknown
```

<details>
<summary><b>可选：配置 Arch Linux / Pacman 升级自动修补 Hook</b></summary>

Pacman Hook 由 `libalpm` 以 `root` 权限直接经 `execv(3)` 调用，不展开 `~` 与 `$HOME`。先将脚本安装至 `root:root` 拥有且普通用户不可写的系统目录，再用 `pacman-hook` 生成 Hook（已内置 `--allow-unknown`）：

```bash
sudo install -D -o root -g root -m 0755 \
  ~/agy-context-unlock/agy_context_unlock.py \
  /usr/local/share/agy-context-unlock/agy_context_unlock.py

sudo mkdir -p /etc/pacman.d/hooks
sudo python3 /usr/local/share/agy-context-unlock/agy_context_unlock.py pacman-hook \
  --script-path /usr/local/share/agy-context-unlock/agy_context_unlock.py \
  --write /etc/pacman.d/hooks/99-agy-context-unlock.hook
```
</details>

```bash
# 卸载还原：从配对备份原子还原原版 /usr/bin/agy
sudo python3 ~/agy-context-unlock/agy_context_unlock.py restore --binary /usr/bin/agy
```

在不具备 root 权限的环境中，亦可使用可选的 `install --patch` 在用户目录下生成只读副本与 `agy-unlock` 包装启动器；完整参数与卸载步骤见 [《CLI 命令参考、安全机制与支持契约》](docs/cli-and-support-scope.md)。

---

## 常用命令速查

| 命令 | 用途说明 |
|---|---|
| `python3 agy_context_unlock.py locate --binary /usr/bin/agy` | 纯只读检查 Go 符号表与 6 处补丁位点的可修补状态 |
| `sudo python3 agy_context_unlock.py patch --binary /usr/bin/agy --in-place --yes --allow-system [--allow-unknown]` | 原地应用 5 处核心补丁并备份/轮换原版（加 `--dry-run` 零写入预演；已实机验证的构建无需 `--allow-unknown`） |
| `python3 agy_context_unlock.py verify --binary /usr/bin/agy` | 只读校验 5 处必选补丁是否均已生效 |
| `sudo python3 agy_context_unlock.py restore --binary /usr/bin/agy` | 从同目录 `.agy-unlock-backup` 原子还原原版二进制 |
| `sudo python3 agy_context_unlock.py pacman-hook --script-path <绝对路径> --write <Hook路径>` | 生成并写入 Pacman `PostTransaction` 自动修补 Hook |
| `python3 agy_context_unlock.py install --patch --scope all --window 900000 [--allow-unknown]` | 可选方式（免 root）：在 `~/.local` 安装只读修补副本与 `agy-unlock` 启动器 |

配套验证与诊断工具包括 `tools/gdb_verify.py`（GDB 零 Token 动态寄存器验证）、`verify_live.py`（端到端跨 256K 实测验证）、`tools/mitm_capture.py`（TLS 脱敏抓包）与离线单元测试（`python3 -B -m unittest discover -s tests -v`）。详见 [《CLI 命令参考、安全机制与支持契约》](docs/cli-and-support-scope.md)。

---

## 文档导航

详细原理、全部命令选项、验证工具与双通道深度取证报告均收纳于 [`docs/`](docs/) 目录：

| 文档 | 内容概要 |
|---|---|
| **[《原理与使用指南》](docs/overview-and-guide.md)** | 面向所有读者的通俗导读：本地压缩触发流程、三种 Token 口径、`/model` 与 `settings.json` 持久化闭环、无头 ACP 模式兜底机制、不同模型家族物理上界、双通道对照与常见误区澄清 |
| **[《CLI 命令参考、安全机制与支持契约》](docs/cli-and-support-scope.md)** | 全部子命令与选项详解、交互式与 ACP 窗口配置、原地修补 / Pacman Hook / 免 root 独立副本部署、GDB 与在线验证工具参考、退出码契约与故障排查 |
| **[《二进制补丁与脚本实现详解》](docs/binary-patch-internals.md)** | ELF64 + Go `pclntab` 动态符号解析、`/model` 持久化写入与读取逆向、5 处核心补丁（约 42 字节）与可选补丁逐字节汇编对比，以及 `1.5.7`→`1.5.14+` 函数改名/返回签名变更的兼容性记录 |
| **[《技术报告：Google OAuth 原生通道》](docs/mechanism-native-oauth.md)** | 原生通道完整代码路径、`ContextWindowMetadata` 本地构造汇编、TLS 抓包键树与逐轮 Token 实测数据（`1.5.1` 原始取证记录） |
| **[《技术报告：企业网关通道》](docs/mechanism-enterprise-gateway.md)** | `/v1beta` 企业网关与自定义模型推导链路、本地反向代理抓包、Gemini 与 DeepSeek 多模型对比实验及证据边界（`1.5.1` 原始取证记录） |

---

## 配套项目与致谢

本项目与以下同系列仓库职责正交，可独立或组合使用：

- **[`antigravity-context-unlock`](https://github.com/MatrixC7/antigravity-context-unlock)**：解除 Antigravity 桌面端引擎（`language_server`）在 Google OAuth 原生通道下的本地上下文自动压缩限制。
- **[`antigravity-uipatch`](https://github.com/MatrixC7/antigravity-uipatch)**：解锁 Antigravity 桌面端被隐藏的原生工作台界面、`Settings -> Developer` 持久化开关及上下文用量与输出速率指示器。
- **[`agy-switch-cli`](https://github.com/MatrixC7/agy-switch-cli)**：面向 Linux 无头与桌面环境的 `agy` 多账号管理、配额巡检与自动/手动凭据切换工具。

社区线索参考：[google-antigravity/antigravity-cli Issue #1245](https://github.com/google-antigravity/antigravity-cli/issues/1245)、[afengblog：Google Antigravity 256K 上下文窗口限制与无头模式政策变更](https://afengblog.com/blog/antigravity-256k-context-discrepancy.html) 及 [linux.do topic/3117832](https://linux.do/t/topic/3117832)。

在机制梳理、脚本实现、文档撰写与实测验证中，主要工作由以下大语言模型协作完成：**Gemini 3.8 Flash**、**Gemini 4 Argon**、**Gemini 4 Neon**、**DeepSeek V4.1 Flash 1017** 与 **GPT-6.1 Sol**；仓库维护者提供了需求设定、运行环境与实机测试条件。谨致谢意。

---

## 许可证

本项目基于 [MIT License](LICENSE) 发布。
