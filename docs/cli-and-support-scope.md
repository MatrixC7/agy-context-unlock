# CLI 命令参考、安全机制与支持契约

> 本文档完整收录 `agy_context_unlock.py`（当前版本 `2.2.0`）的全部子命令与选项说明、交互式与 ACP 无头模式的窗口配置方式、原地修补与可选部署流程（Pacman 自动 Hook、免 root 独立副本）、验证与抓包工具、安全防护机制、退出码契约与常见故障排查。
> - 通俗概念导读与双通道差异见 [《原理与使用指南》（`overview-and-guide.md`）](overview-and-guide.md)
> - 底层 ELF64 / Go `pclntab` 解析与 5 处核心补丁（39–42 字节）反汇编细节见 [《二进制补丁与脚本实现详解》（`binary-patch-internals.md`）](binary-patch-internals.md)
> - 双通道原始实验报告见 [《Google OAuth 原生通道技术报告》（`mechanism-native-oauth.md`）](mechanism-native-oauth.md) 与 [《企业网关通道技术报告》（`mechanism-enterprise-gateway.md`）](mechanism-enterprise-gateway.md)

---

## 1. CLI 子命令与全部选项详解（`agy_context_unlock.py`）

### 1.1 子命令速查表

| 子命令 | 是否修改磁盘文件 | 核心作用 |
|---|:---:|---|
| `locate` | 否（纯只读） | 解析 ELF64 与 Go `pclntab` 符号表，列出全部 6 个补丁位点（5 处必选 + 1 处可选）的虚拟地址、偏移与当前状态（`patchable` / `already patched` / `NOT FOUND`） |
| `patch` | 是（加 `--dry-run` 时不写盘） | 应用 5 处必选补丁（及可选 `default-clamp`），默认输出到 `<BINARY>.patched`，加 `--in-place` 时原地备份（或增量保留干净备份）并覆盖 |
| `verify` | 否（纯只读） | 校验目标二进制中 5 处必选补丁是否均已生效 |
| `restore` | 是 | 从备份文件（默认 `<BINARY>.agy-unlock-backup`）原子还原原版二进制 |
| `self-test` | 否（纯只读） | 面向 `1.5.7` 锚点构建的严格离线自检：核对 7 个固定锚点符号虚拟地址及内存中施加 5 处必选补丁后的精确字节变更数（42 字节） |
| `pacman-hook` | 仅带 `--write` 时写盘 | 生成或写入 Arch Linux / EndeavourOS / CachyOS 的 Pacman `PostTransaction` Hook 文件 |
| `install` | 是 | 可选方式（免 root）：安装独立副本与 `agy-unlock` 包装启动器至指定前缀目录（默认 `~/.local`） |

### 1.2 全局与各子命令选项说明

- **顶层选项**
  - `--version`：打印脚本版本号（当前为 `2.2.0`）并退出。
  - `-h` / `--help`：打印顶层或对应子命令的帮助信息。
- **全部子命令通用选项**
  - `--binary <path>`：目标 `agy` 二进制路径，默认 `/usr/bin/agy`。
  - `--json`：在支持的命令（`locate`）下附带输出 JSON 结构化信息。
- **`patch` 专属选项**
  - `--out <path>`：指定修补后二进制的输出路径（未传 `--in-place` 且未传 `--out` 时，默认写入 `<BINARY>.patched`）。
  - `--in-place`：原地覆盖目标二进制，并在写盘前自动备份、增量保留干净原版备份或轮换同目录的 `<BINARY>.agy-unlock-backup`。
  - `--yes`：确认覆盖源二进制（当输出路径解析为源二进制时必传）。
  - `--allow-system`：允许原地覆盖系统路径 `/usr/bin/agy` 或 `/usr/local/bin/agy`。
  - `--dry-run`：仅在内存中匹配并预演补丁，不向磁盘写入任何文件。
  - `--patches <list>`：以逗号分隔仅应用指定子集，可选值为 `ui-selector`、`store-gate`、`settings-window`、`model-gate`、`acp-override`、`default-clamp`。
  - `--with-default-clamp`：额外启用可选第 6 项补丁 `default-clamp`，将未设置窗口档位时的本地兜底 `256000` 钳位提升至 `1048576`（默认不启用，使 `/model` 中的“默认”档位与未设环境变量的 ACP 会话保持原厂行为）。
  - `--allow-unknown`：当目标二进制 SHA256 不是脚本内置的 `1.5.7` 锚点构建（例如已升级至 `1.5.8`–`1.5.14` 等兼容小版本）时放行结构化匹配；若任一必选补丁签名不匹配仍会安全中止。
- **`restore` 专属选项**
  - `--backup <path>`：手动指定要还原的备份路径（默认为 `<BINARY>.agy-unlock-backup`；如需回退到轮换出的旧备份 `.agy-unlock-backup.<SHA前8位>` 可由此指定）。
- **`pacman-hook` 专属选项**
  - `--package <name>`：Hook 监听的 Pacman 软件包名，默认 `antigravity-cli`。
  - `--script-path <path>`：写入 Hook `Exec` 行的 `agy_context_unlock.py` 路径，默认取当前正在运行的脚本绝对路径。
  - `--write <path>`：将生成的 Hook 原子写入目标路径（如 `/etc/pacman.d/hooks/99-agy-context-unlock.hook`）；省略时仅打印至标准输出。
- **`install` 专属选项**
  - `--prefix <dir>`：安装根目录，默认 `~/.local`（启动器写入 `<prefix>/bin/agy-unlock`，独立副本与状态文件写入 `<prefix>/share/agy-context-unlock/`）。
  - `--window <tokens>`：包装启动器注入 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 的目标窗口大小（范围 `1..1000000`，默认 `900000`）。
  - `--scope <native-gemini|all>`：控制包装启动器在哪些模型下注入环境变量。`native-gemini`（默认）仅对 Google 原生 Gemini 生效；`all` 对所有模型（含企业网关自定义模型）生效。
  - `--patch`：将修补后的二进制副本写入 `<prefix>/share/agy-context-unlock/agy`，并将该副本与目录设为 `0555` 只读以阻止内置自动更新器覆盖；不加 `--patch` 时启动器直接调用系统原始 `--binary`。
  - `--shadow`：在 `<prefix>/bin/agy` 额外创建一个转发至 `agy-unlock` 的包装脚本（仅当 `<prefix>/bin` 位于 `PATH` 中 `/usr/bin` 之前时生效，且若已存在同名文件不会覆盖）。
  - `--allow-unknown`：对非 `1.5.7` 锚点 SHA256 的兼容构建放行安装。

### 1.3 补丁生效后的窗口配置方式（交互式与 ACP 无头模式）

应用 5 处核心补丁（`1.5.7` 锚点共 42 字节，`1.5.14+` 为 39 字节）后，交互式日常使用**无需包装启动器，也无需每次在终端传入环境变量**；同时 `agy acp` 无头模式（如 T3 Code）可通过宿主环境变量直接配置。各方式按如下规则协同工作：

1. **交互式 CLI：通过 `/model` 菜单切换（自动持久化）**
   - 启动 `agy` 后输入 `/model` 打开模型选择器。
   - 按 **`Tab` 键**在 `默认`、`256K`、`512K`、`900K` 四档之间循环切换 `Context` 指示器。
   - 按 **`Enter` 键**确认。`agy` 会调用 `SetContextWindow` → `WriteCliSettings`，自动将 `"contextWindow": "900K"` 写入 `~/.gemini/antigravity-cli/settings.json` 并同步至当前会话；此后每次启动 `agy` 均会自动读取生效。
2. **交互式 CLI：直接编辑 `settings.json`（持久化）**
   - 在 `~/.gemini/antigravity-cli/settings.json` 中写入 `"contextWindow": "900K"`（亦支持 `"512K"` 或 `"256K"`）。
   - 交互模式与 `-p` 非交互模式启动时均会自动读取该字段。
3. **环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE`（交互式最高优先级覆盖 + ACP 无头模式主入口）**
   - **在交互式 CLI（`agy` / `agy -p`）中**：引擎在读取 `settings.json` 之前先检查 `AGY_CLI_AUTO_COMPACT_OVERRIDE`。适合在脚本中临时指定任意整数阈值（例如 `600000`，或在 Argon / Flash 上释放至物理上界 `983040`），或针对企业网关中容量较小的自定义模型单独限流：
     ```bash
     AGY_CLI_AUTO_COMPACT_OVERRIDE=600000 agy -p "hello"
     ```
   - **在 ACP 无头模式（`agy acp`，如 T3 Code）中**：`agy acp` 不会初始化交互式 `store.Manager`，也不读取 `settings.json` 中的 `"contextWindow"`。应用第 5 处补丁 `acp-override` 后，在宿主对应提供方环境变量（例如 T3 Code 的「设置 → 智能体提供方 → Antigravity → 环境 → 变量」）中添加 `AGY_CLI_AUTO_COMPACT_OVERRIDE=900K`（注意 `K` 须大写，亦可填整数如 `900000`）并**新开会话**（或重启宿主服务以重建 `agy acp` 子进程）即可直接生效；未设置该变量时维持原厂默认行为。

### 1.4 部署方式一：原地修补 `/usr/bin/agy` 与升级轮换

将仓库克隆到 `~/agy-context-unlock`，先用只读 `locate` 检查签名，再原地修补：

```bash
git clone https://github.com/MatrixC7/agy-context-unlock.git ~/agy-context-unlock
cd ~/agy-context-unlock

# 1. 只读检查目标函数与 5 处必选（共 6 处）补丁位点
python3 agy_context_unlock.py locate --binary /usr/bin/agy

# 2. 原地修补 /usr/bin/agy（自动创建原版备份 /usr/bin/agy.agy-unlock-backup）
#    若当前安装的是 1.5.7 之后的兼容版本（如 1.5.12–1.5.14），请加上 --allow-unknown
sudo python3 ~/agy-context-unlock/agy_context_unlock.py patch \
  --binary /usr/bin/agy --in-place --yes --allow-system --allow-unknown

# 3. 校验 5 处必选补丁状态
python3 ~/agy-context-unlock/agy_context_unlock.py verify --binary /usr/bin/agy
```

> 若系统仍停留在 `agy` `1.5.5`（或更早版本），请先执行 `git checkout v1.5.5`，否则 `1.5.7+` 的 `settings-window` 签名不会匹配。

升级、增量修补与旧备份轮换机制：
- 由于 `/usr/bin/agy` 属主为 `root:root`，普通用户权限下运行的 `agy` 内置后台更新器不会覆盖该系统二进制。
- 当再次执行上述 `patch --in-place --yes --allow-system --allow-unknown` 时，脚本会按以下三种情形保护备份：
  - **既有备份与源二进制哈希一致**：直接复用现有备份。
  - **同版本增量叠加新补丁**（例如已应用旧版 4 处补丁，升级本工具后补充应用第 5 处补丁 `acp-override`）：脚本将当前源二进制上已存在的补丁在内存中重放至既有 `.agy-unlock-backup` 并比对 SHA256；吻合时打印 `keeping existing clean backup` 并**原地保留该干净原版备份**，不轮换也不覆盖。
  - **软件包升级导致哈希不一致且重放不匹配**：先将旧备份重命名为 `/usr/bin/agy.agy-unlock-backup.<旧SHA前8位>`，再把当前新版原厂二进制备份为 `/usr/bin/agy.agy-unlock-backup`，防止日后执行 `restore` 时误将系统降级到旧版本。

### 1.5 部署方式二（可选）：Arch Linux / Pacman 升级自动修补 Hook

在 Arch Linux、EndeavourOS 或 CachyOS 上，可配置 Pacman `PostTransaction` Hook，在 `antigravity-cli` 安装或升级后自动重新修补（Hook 模板默认已带 `--allow-unknown`）。

部署时请注意以下规则：
- Pacman Hook 文件由 `libalpm` 直接解析并经 `execv(3)` 执行，不经过任何 shell，因此 `Exec` 行中的 `~` 与 `$HOME` 不会被展开，必须填写完整绝对路径。
- 鉴于 Hook 以 `root` 权限运行，从安全边界出发，建议先将单文件脚本安装到 `root:root` 拥有且普通用户不可写的系统目录（如 `/usr/local/share/agy-context-unlock/`），再生成 Hook；亦可直接使用 `pacman-hook --script-path` 指向实际绝对路径。

```bash
# 推荐的系统只读目录部署方式
sudo install -D -o root -g root -m 0755 \
  ~/agy-context-unlock/agy_context_unlock.py \
  /usr/local/share/agy-context-unlock/agy_context_unlock.py

sudo mkdir -p /etc/pacman.d/hooks
sudo python3 /usr/local/share/agy-context-unlock/agy_context_unlock.py pacman-hook \
  --script-path /usr/local/share/agy-context-unlock/agy_context_unlock.py \
  --write /etc/pacman.d/hooks/99-agy-context-unlock.hook
```

仓库亦在 [`pacman/99-agy-context-unlock.hook`](../pacman/99-agy-context-unlock.hook) 提供了可手动参考的模板文件。若使用系统目录副本，在仓库更新适配新版本后，请重新执行上述 `sudo install` 覆盖副本。

### 1.6 部署方式三（可选、免 root）：独立只读副本与 `agy-unlock` 包装启动器

在不具备 root 权限或不希望修改 `/usr/bin/agy` 的环境下，可使用 `install` 子命令在用户前缀目录（默认 `~/.local`）下生成独立修补副本与 `agy-unlock` 包装启动器：

```bash
# 在 ~/.local/share/agy-context-unlock/agy 生成修补后的只读副本，
# 并在 ~/.local/bin/agy-unlock 生成启动器（非 1.5.7 锚点构建请加 --allow-unknown）
python3 ~/agy-context-unlock/agy_context_unlock.py install \
  --patch --scope all --window 900000 --allow-unknown

export PATH="$HOME/.local/bin:$PATH"
agy-unlock --model "Gemini 3.8 Flash (High)"
```

该模式的运行细节如下：
- **防自动更新器覆盖**：启用 `--patch` 后，脚本会将 `~/.local/share/agy-context-unlock/agy` 及其所在目录设为 `0555` 只读权限，防止内置更新器悄悄替换修补后的副本。后续需要重装或升级该副本时，需先执行 `chmod u+w ~/.local/share/agy-context-unlock`。
- **启动器环境变量**：`agy-unlock` 支持以下运行期环境变量覆盖：
  - `AGY_UNLOCK_BINARY`：覆盖启动器调用的目标二进制路径。
  - `AGY_UNLOCK_WINDOW`：覆盖默认注入的 Token 窗口值（`1..1000000`）。
  - `AGY_UNLOCK_KEEP_ENV=1`：当模型不在 `--scope` 范围内时保留调用方手动设置的 `AGY_CLI_AUTO_COMPACT_OVERRIDE`（默认会清除）。
  - `AGY_UNLOCK_VERBOSE=1`：向标准错误输出解析出的 `model`、`provider`、`scope` 与最终环境变量值，便于排查。

### 1.7 一键还原与卸载清理

- **还原原地修补的系统二进制**：
  ```bash
  sudo python3 ~/agy-context-unlock/agy_context_unlock.py restore --binary /usr/bin/agy
  sudo rm -f /etc/pacman.d/hooks/99-agy-context-unlock.hook
  sudo rm -rf /usr/local/share/agy-context-unlock
  ```
- **清理免 root 独立副本与启动器**（如曾使用 `install` 模式）：
  ```bash
  chmod -R u+w ~/.local/share/agy-context-unlock 2>/dev/null || true
  rm -rf ~/.local/share/agy-context-unlock ~/.local/bin/agy-unlock
  # 若曾使用 --shadow 创建 ~/.local/bin/agy，一并删除：
  # rm -f ~/.local/bin/agy
  ```

---

## 2. 验证、抓包与离线测试工具

### 2.1 静态状态校验：`locate`、`verify` 与 `self-test` 的区别

- **`locate`**：适用于任意兼容版本（包括 `1.5.7` 及后续 `1.5.12`–`1.5.14` 等小版本），按 Go 符号名动态定位函数并检查全部 6 个补丁位点（5 处必选 + 1 处可选）的匹配情况（纯只读）。
- **`verify`**：适用于任意兼容版本，检查 5 处必选补丁的修改后字节是否均已存在，全部存在返回退出码 `0`（纯只读）。
- **`self-test`**：面向 **`1.5.7` 锚点构建**的严格回归检查，除验证内存中精确修改 42 字节外，还会比对 7 个硬编码的 `1.5.7` 函数虚拟地址；在其他版本上运行会因符号地址自然偏移而报告地址项 `[FAIL]`，此时请以 `locate` 与 `verify` 为准。

### 2.2 GDB 零 Token 动态寄存器验证（`tools/gdb_verify.py`）

通过 GDB 启动 `agy`（测试期自动设置 `AGY_CLI_DISABLE_AUTO_UPDATE=1` 并将 `stdin` 重定向自 `/dev/null`），在配置构造函数 `backend.(*ServerBackend).buildCascadeConfigInternal` 返回前（尚未发出任何网络推理请求，消耗 **0 Token**）读取上下文窗口相关寄存器并终止进程。5 个断点偏移均由 `acp-override` 与 `model-gate` 符号位点及函数内写入/返回指令动态推导，不写死绝对虚拟地址，可跨 `1.5.7`–`1.5.14+` 自动适配栈槽位移。

全部选项：
- `--binary <path>`：待测 `agy` 二进制路径（默认 `/usr/bin/agy`）。
- `--models <list>`：逗号分隔的测试模型列表（默认 `Gemini 4 Argon (High),Gemini 3.8 Flash (High)`）。
- `--proxy <url>`：出站代理地址（默认继承 `HTTPS_PROXY`，未设置时回退 `http://127.0.0.1:2080`）。
- `--override <value>`：可选，测试时传入 `AGY_CLI_AUTO_COMPACT_OVERRIDE`（默认不设置，用于验证 `settings.json` 直接生效）。

```bash
python3 ~/agy-context-unlock/tools/gdb_verify.py --binary /usr/bin/agy
```

当 `~/.gemini/antigravity-cli/settings.json` 中已配置 `"contextWindow": "900K"` 且未设置环境变量时，预期输出如下：

```text
== Gemini 4 Argon (High) ==
  CTXWINDOW_STRING_LEN=4
  CTXWINDOW_LIMIT=900000
  PROTO_EQUAL=1
  WRITE_MAXTOKEN=900000
  CONFIG_RETURN_BEFORE_REQUEST=1
  status=killed_before_config_return
```

未修补原版在同一条件下仅输出 `CTXWINDOW_STRING_LEN=0` 与 `CTXWINDOW_LIMIT=0`，不会写入 `MaxTokenLimit`。

### 2.3 端到端长对话实测验证（`verify_live.py`）

生成确定性随机英文填充文件或多轮 NDJSON 输入驱动 `agy` 跨过 256K 上下文，随后以双重只读方式（`mode=ro` + `PRAGMA query_only=ON`）读取 `~/.gemini/antigravity-cli/conversations/<cid>.db` 的 `gen_metadata` 表，验证最高估算值跨过 256K 且未发生早期压缩。脚本仅解码数值元数据，不打印对话正文。

全部命令行选项：

| 选项 | 默认值 | 说明 |
|---|---|---|
| `--binary <path>` | `/usr/bin/agy` | 待测 `agy` 二进制路径 |
| `--model <name>` | `Gemini 3.8 Flash (High)` | 测试模型名 |
| `--mode <files\|stream>` | `files` | `files` 让模型读取填充文件；`stream` 发送多轮 NDJSON 用户消息 |
| `--files <N>` | `6` | `files` 模式下生成的 400 KB 填充文件个数（默认 6 个约 450K tokens） |
| `--turns <N>` | `30` | `stream` 模式下发送的用户轮数 |
| `--turn-bytes <N>` | `60000` | `stream` 模式下每轮填充字节数 |
| `--window <tokens>` | `900000` | 传递给 `agy` 的窗口覆盖值（`1..1000000`） |
| `--no-override` | 否 | 负向对照组：不注入环境变量（不可与 `agy-unlock` 启动器同时使用） |
| `--proxy <url>` | 继承 `HTTPS_PROXY` | 模型 API 使用的 HTTPS 代理 |
| `--timeout <sec>` | `2400` | 运行超时时间（秒） |
| `--workdir <dir>` | 自动临时目录 | 指定父目录并在其下新建 `run-<timestamp>` 子目录（显式指定时永不自动删除） |
| `--keep` | 否 | 保留自动创建的临时工作目录 |
| `--allow-failure` | 否 | 即使 `agy` 非零退出仍尝试解析已生成的会话数据库 |

使用示例：

```bash
# 正向验证：确认跨过 256K 且无早期压缩
python3 ~/agy-context-unlock/verify_live.py \
  --binary /usr/bin/agy --model "Gemini 3.8 Flash (High)" \
  --files 6 --window 900000 --proxy http://127.0.0.1:7890

# 负向对照：对未修补二进制验证会在 256K 附近触发压缩
python3 ~/agy-context-unlock/verify_live.py \
  --binary /usr/bin/agy.agy-unlock-backup --no-override \
  --model "Gemini 3.8 Flash (High)" --files 4
```

### 2.4 TLS 脱敏流量抓包插件（`tools/mitm_capture.py`）

适用于 `mitmproxy` / `mitmdump` 的脱敏审计插件，仅记录请求与响应的 JSON 键树结构、配置数值字段与 Token 统计，绝不写入消息正文、工具输出、文件内容或鉴权请求头，输出文件自动设为 `0600` 权限。

- 环境变量 `CAPTURE_OUT`：指定 JSONL 输出路径，默认 `/tmp/agy-tls-capture.jsonl`。

```bash
CAPTURE_OUT=/tmp/agy-capture.jsonl mitmdump -s ~/agy-context-unlock/tools/mitm_capture.py -p 8080
```

### 2.5 离线单元测试套件

包含解析器单元测试（`tests/test_parser.py`）与安全边界及压缩判定测试（`tests/test_safety.py`）；若本机未放置 `1.5.7` 锚点构建，依赖 `1.5.7` 原版二进制的用例会自动跳过，其余纯离线安全测试正常执行：

```bash
python3 -B -m unittest discover -s ~/agy-context-unlock/tests -v
```

---

## 3. 安全防护机制与已知运行边界

### 3.1 安全防护设计

- **函数边界内唯一精确匹配**：每个补丁均先经 `pclntab` 解析目标函数范围 `[fn.va, fn.end)`，且映射至可执行节/段（`SHF_EXECINSTR` / `PF_X`），并要求目标机器码在函数内唯一匹配（或精确命中指定序号）。
- **先内存全量预演、后原子写盘**：`patch` 会在内存中依次应用全部必选补丁；只要任意一项签名不匹配，脚本立即以退出码 `3` 返回，绝不写入磁盘，不会留下半修补二进制。
- **系统二进制保护与显式确认**：原地覆盖 `/usr/bin/agy` 或 `/usr/local/bin/agy` 时强制要求同时传入 `--in-place --yes --allow-system`；非锚点 SHA256 构建强制要求显式 `--allow-unknown`。
- **原子替换、增量干净备份保留与旧备份自动轮换**：写盘通过同目录临时文件 + `fsync` + 保留原文件权限 + `os.replace` 实现；原地增量叠加新补丁时通过内存重放哈希校验保留原有干净备份；跨软件包升级导致既有备份与当前源二进制哈希不同时，自动轮换为 `.agy-unlock-backup.<旧SHA前8位>` 后再创建新备份。

### 3.2 已知运行边界

- **本地预算上限受模型物理窗口约束**：即使在 `/model` 或 `settings.json` 中选择 `"900K"`，引擎下游仍会执行 `utils.ClampCheckpointConfigForModelInfo` 按 `MaxTokens - MaxOutputTokens` 保护输出预留：
  - `Gemini 4 Argon` / `Gemini 3.8 Flash`：`900,000`（物理上界 `983,040`，可通过 `AGY_CLI_AUTO_COMPACT_OVERRIDE=983040` 进一步接近上界）。
  - `Claude Opus 5.5` / `Claude Sonnet 5.5`：自动钳位至 **`872,000`**（`1,000,000 - 128,000`）。
  - `Gemini 4 Carbon`：自动钳位至 **`786,432`**（`1,048,576 - 262,144`）。
- **企业网关小窗口自定义模型提醒**：企业网关的 `/v1beta/models` 通常不下发真实 `maxTokens`。当调用物理上下文小于 `900K`（如 128K 或 256K）的第三方自定义模型时，若本地预算高于上游真实窗口，超限时上游 API 会返回错误；此时请在 `/model` 中切回 `256K` / `512K` 或通过 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 设定匹配容量。
- **不适用于桌面端应用**：本工具仅面向命令行工具 `/usr/bin/agy`。Antigravity 桌面端引擎 `/opt/Antigravity/resources/bin/language_server` 需使用 [`antigravity-context-unlock`](https://github.com/MatrixC7/antigravity-context-unlock)。

---

## 4. 支持范围、退出码契约与常见故障排查

### 4.1 支持范围与版本归档策略

| 项目 | 说明 |
|---|---|
| 目标平台 | Linux x86-64（ELF64 小端序 Go 1.18+ PIE 二进制） |
| 运行依赖 | Python 3 标准库（零第三方包依赖；`tools/gdb_verify.py` 另需 `gdb`，`tools/mitm_capture.py` 另需 `mitmproxy`） |
| 当前 `main` 适配线 | `antigravity-cli >= 1.5.7`（锚点验证构建 `1.5.7`，`SHA256: 5df525a2d6908989c57b897723caea66e00d7c4d2e24411f91ad306989574642`；后续兼容构建如 `1.5.12`–`1.5.14` 可经 `--allow-unknown` 直接定位并修补，`model-gate` / `acp-override` 采用调用符号锚定） |
| 历史版本归档 | 仓库标签 **`v1.5.5`** 保留了 `1.5.7` 结构体变动前的补丁线（适用于 `1.5.1`–`1.5.5`，`Store.featureProvider` 位于 `+0xb8`） |

### 4.2 退出码契约

| 退出码 | `agy_context_unlock.py` | `verify_live.py` | `tools/gdb_verify.py` |
|---:|---|---|---|
| `0` | 操作成功、`verify` 确认全部必选补丁已存在，或 `patch --dry-run` / 幂等重复 `patch` 通过 | 成功跨过 256K 且未发生 `<= 256K` 的早期压缩 | 成功读取目标寄存器并在发请求前终止进程 |
| `1` | `verify` 或 `self-test` 校验失败，或底层 `BinaryError`（ELF/符号解析异常） | 未跨过 256K 或发生早期压缩 | —（GDB 子进程异常退出时抛出非零错误） |
| `2` | 文件不存在、参数非法、SHA256 非锚点且未传 `--allow-unknown`、缺少 `--yes` / `--allow-system` 或备份不存在 | 参数非法、二进制不存在或 `--no-override` 与启动器冲突 | 二进制不存在，或无法在目标二进制中定位 `acp-override` / `model-gate` / 写入返回断点 |
| `3` | 必选补丁签名在目标函数内未命中或出现歧义（未写入任何文件） | 运行日志中未找到会话 ID | — |
| `4` | — | `agy` 子进程非零退出且未传 `--allow-failure` | — |

### 4.3 常见故障排查

- **报错 `SHA256 ... is not the verified 1.5.7 build; use --allow-unknown to override`**
  - 原因：本机 `antigravity-cli` 已升级到 `1.5.7` 之后的新小版本（如 `1.5.12`–`1.5.14`），脚本默认开启锚点哈希保护。
  - 处理：先运行 `python3 ~/agy-context-unlock/agy_context_unlock.py locate --binary /usr/bin/agy` 确认 5 处必选补丁均显示 `patchable`（或 `already patched`），再在 `patch` 命令中追加 `--allow-unknown`。
- **报错 `settings-window: expected bytes not found in store.(*Store).ContextWindow`**
  - 原因：本机安装的是旧版 `agy`（`1.5.5` 或更早，字段偏移为 `+0xb8`），或未来新版再次调整了 `Store.featureProvider` 偏移。
  - 处理：脚本已安全中止且未改写二进制。若本机为 `1.5.5` 或更早版本，执行 `git checkout v1.5.5` 后重试；若为更新版本，则需等待针对新偏移的签名更新。
- **运行 `self-test` 显示 7 个符号地址 `[FAIL]`，但 `verify` 显示 `verified`**
  - 原因：`self-test` 内置了 `1.5.7` 的绝对虚拟地址断言，新版 `agy` 重新编译后函数地址自然整体漂移，属于正常现象。
  - 处理：以 `locate` 与 `verify` 的动态结构校验结果为准。
- **在 T3 Code 等 ACP 无头宿主中设置了 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 但未生效**
  - 原因：环境变量写到了其他提供方（如 Codex）名下、使用了小写 `k`（如 `900k` 而非 `900K` / `900000`）、`/usr/bin/agy` 尚未应用 `v2.2.0` 的 `acp-override` 补丁，或旧会话仍在复用修补前的 `agy acp` 常驻子进程。
  - 处理：运行 `verify --binary /usr/bin/agy` 确认 `acp-override` 为 `PATCHED`；确认环境变量配置在 **Antigravity** 提供方下且值为 `900K` 或 `900000`；随后**新开一个 Antigravity 对话**（或重启宿主服务以重建 `agy acp` 进程）。
- **Pacman 升级后 Hook 没有自动生效**
  - 原因：手写 `/etc/pacman.d/hooks/99-agy-context-unlock.hook` 时在 `Exec` 中使用了 `~` 或 `$HOME`（`libalpm` 不经过 shell 不会展开），或未包含 `--allow-unknown`。
  - 处理：使用 `pacman-hook --script-path <绝对路径> --write ...` 重新生成 Hook 文件。
- **重装 `install --patch` 副本时提示权限拒绝**
  - 原因：`install --patch` 会将 `~/.local/share/agy-context-unlock` 设为 `0555` 只读以阻止内置更新器。
  - 处理：先执行 `chmod u+w ~/.local/share/agy-context-unlock` 再重新运行 `install`。
