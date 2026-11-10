# 二进制补丁与脚本实现详解（`agy_context_unlock.py`）

> 本文档面向开发者、系统管理员与逆向工程研究人员，详细说明 `agy_context_unlock.py` 的内部实现原理、Go 1.18+ 符号表动态定位算法、4 处核心补丁（20 字节）的 x86-64 反汇编前后对比，以及 `/model` 交互菜单将上下文窗口持久化至 `settings.json` 的完整调用链。

---

## 1. 设计目标与架构概览

`antigravity-cli`（`/usr/bin/agy`）是一个体积约 240 MB 的 Go 语言编译生成的 Linux x86-64 PIE（位置无关可执行）二进制文件。为了在不依赖外部工具链的前提下安全、可靠地解除其 256K 本地上下文压缩限制，`agy_context_unlock.py` 采用以下架构设计：

1. **零外部依赖**：完全基于 Python 3 标准库（`struct`、`hashlib`、`tempfile` 等）实现 ELF64 与 Go `pclntab` 解析，无需安装 `objdump`、`radare2` 或任何第三方 Python 包即可独立运行。
2. **动态符号定位而非硬编码文件偏移**：先通过 Go 运行时符号表找到目标函数的精确起止边界 `[fn.va, fn.end)`，再在函数内部匹配唯一的指令签名（instruction signature）。即使小版本更新导致函数地址整体偏移，只要目标函数内部逻辑未变，脚本仍可利用 `--allow-unknown` 自动完成定位与修补。
3. **打通原生持久化配置闭环**：通过恢复 `store.(*Store).ContextWindow` 到 `store.(*Store).ContextWindowChoice` 的调用链，使 `~/.gemini/antigravity-cli/settings.json` 与交互式 `/model` 菜单直接生效，无需依赖外部包装脚本（wrapper）或终端环境变量。

---

## 2. ELF64 与 Go `pclntab` 动态符号解析器

脚本的第一部分（`ELFFile` 与 `GoSymbols` 类）负责从二进制文件中还原出全部 Go 函数的名称与虚拟地址区间：

```text
[读取 ELF64 二进制文件]
        │
        ▼
1. 解析 Section 与 Segment 映射 (ELFFile)
   ├── 校验 ELF64 小端序与 x86-64 架构 (e_machine == 0x3e)
   ├── 提供虚拟地址与文件偏移的双向转换 (va_to_off / off_to_va)
   ├── 提供可执行权限校验 (va_to_off_exec: 检查 SHF_EXECINSTR=0x4 与 PF_X=0x1)
   └── 扫描 SHT_RELA 动态重定位表，提取所有 R_X86_64_RELATIVE (type 8) 映射
        │
        ▼
2. 定位 Go 运行时主函数表 (GoSymbols._find_pclntab)
   ├── 搜索 Go 1.18+ pclntab 魔数 0xFFFFFFF1 (小端字节 f1 ff ff ff 00 00)
   ├── 校验 minLC (1/2/4)、指针宽度 (8)、函数数量 nfunc 及首函数名可见性
   └── 结合 SHT_RELA 重定位表，优先选择被 runtime.moduledata 引用的主表
       （在 agy 1.5.1 中，主表位于 0x1680900，包含 nfunc = 178,096 个函数）
        │
        ▼
3. 推导代码段基址与函数边界 (_find_text_base & _build)
   ├── 在 PIE 构建中，pclntab 表头的 textStart 为 0，函数表记录的是相对偏移 entryoff
   ├── 脚本通过指向 pclntab_va 的重定位槽定位 moduledata 结构体（1.5.1 中为 0xc8f6e40），
   │   读取其 +0xa0 (minpc) 与 +0xb0 (text) 槽位，获得精确代码基址 text_base = 0x69cb080
   └── 遍历 178,096 个函数的 (entryoff, funcoff)，计算每个函数的虚拟地址 va = text_base + entryoff
       及下一函数起点 end，构建完整的符号查找表
```

在 `agy` 1.5.1 上运行 `python3 agy_context_unlock.py locate --binary /usr/bin/agy`，解析器定位到的 5 个关键锚点函数如下：

| 符号后缀 | 虚拟地址（VA） | 函数结束地址 | 作用 |
|---|---:|---:|---|
| `model.SelectorModel.offersContextWindow` | `0x9e872e0` | `0x9e874e0` | 控制 `/model` 菜单是否显示 `Context` 档位切换器 |
| `store.(*Store).ContextWindowChoice` | `0x9c34b40` | `0x9c34b80` | 读取并校验 `settings.json` 中的 `"contextWindow"` 字段 |
| `store.(*Store).ContextWindow` | `0x9c34b80` | `0x9c34e00` | 解析当前生效的上下文窗口字符串（白名单、环境变量、配置文件） |
| `backend.(*ServerBackend).buildCascadeConfigInternal` | `0x9888380` | `0x9889160` | 将上下文窗口上限写入 `CheckpointConfig.MaxTokenLimit` |
| `utils.GetCheckpointConfig` | `0x7fb0ec0` | `0x7fb1400` | 推导模型默认 Checkpoint 配置（含 `256000` 兜底钳位） |

---

## 3. 交互式 `/model` 菜单与 `settings.json` 持久化的逆向分析

许多用户与开发者关心一个问题：**在 `/model` 菜单中手动切换上下文长度（`256K` / `512K` / `900K`）后，该设置是否会自动持久化（下次启动依然保留）？其底层是如何实现的？**

通过对 `google3/third_party/jetski/cli/model/model.SelectorModel` 与 `store.Manager` 相关函数的完整反汇编，证实 **`agy` 原生已完整实现了 `/model` 切换后的磁盘持久化写入逻辑**，具体执行链路如下：

### 3.1 打开 `/model` 时的状态回显与按键绑定
1. **按键提示渲染（`SelectorModel.gaugeHints`，`0x9e87ca0`）**：
   - 在 `0x9e87e50` 处调用 `offersContextWindow`（`0x9e872e0`）。当返回 `true` 时，向底部快捷键栏追加 `KeyTab`（`0xa8def00`）→ `"Context"`（`0xa8defb0`）提示。
2. **当前档位回显（`SelectorModel.windowFor`，`0x9e876c0`）**：
   - `renderContextChip`（`0x9e88317`）调用 `windowFor` 获取当前模型显示的档位。
   - 若用户在本次打开菜单期间尚未按过 `Tab` 键修改档位，`windowFor` 在 `0x9e87791..0x9e877ab` 处执行：
     ```text
     9e87791: mov  (%rcx), %rcx        # 获取 Store 实例
     9e87794: mov  0x10(%rcx), %rcx    # 获取 Store.cliSetting (*types.CliSetting)
     9e877a3: mov  0x70(%rcx), %rax    # 读取 cliSetting.ContextWindow 字符串指针
     9e877a7: mov  0x78(%rcx), %rbx    # 读取 cliSetting.ContextWindow 字符串长度
     9e877ab: call 0x98755e0           # 调用 backend.ParsePresetContextWindow 校验 "256K"/"512K"/"900K"
     ```
     也就是说，每次打开 `/model` 菜单时，UI 直接从 `settings.json` 对应的内存结构 `cliSetting.ContextWindow` 读取已保存的档位进行展示。

### 3.2 按 `Tab` 键循环切换档位
- 在 `/model` 界面按下 **`Tab` 键**时，`SelectorModel.Update`（`0x9e83208`）检查 `offersContextWindow` 为 `true` 后，在 `0x9e832e8` 调用 `(*SelectorModel).cycleWindow`（`0x9e87960`）。
- `cycleWindow` 构建包含 4 个元素的档位数组 `["" (默认), "256K", "512K", "900K"]`（见 `0x9e8798e..0x9e879de`，分别引用常量字符串 `0x5cad425` `"256K"`、`0x5cad415` `"512K"`、`0x5cad41d` `"900K"`），将当前档位索引加 1 取模（`idx = (idx + 1) % 4`），并将新档位暂存至 `SelectorModel` 的 `windowOverrides` 映射表中。

### 3.3 按 `Enter` 键确认时的磁盘持久化（写入 `settings.json`）
- 当用户按下 **`Enter` 键**确认选择时，触发 `SelectorModel.selectRow`（`0x9e84380`）：
  1. 在 `0x9e844a0` 调用 `SelectorModel.windowToSave`（`0x9e877e0`），检查 `windowOverrides` 中是否有新的上下文窗口选择，并与当前 `cliSetting.ContextWindow` 比较是否发生变更。
  2. 若发生变更，在闭包 `SelectorModel.selectRow.func1`（`0x9f416c0`）的 `0x9f4171a` 处调用 **`store.(*Manager).SetContextWindow`（`0x9c34e00`）**。
  3. `SetContextWindow` 复制当前 `Store.cliSetting` 结构体，将新的窗口字符串写入偏移 `+0x70` / `+0x78`（即 `ContextWindow` 字段，JSON 标签为 `json:"contextWindow,omitempty"`），随后在 `0x9c34f41` 调用 **`store.(*Manager).WriteCliSettings`（`0x9c26280`）**。
  4. `WriteCliSettings` 将更新后的配置序列化写入磁盘文件 **`~/.gemini/antigravity-cli/settings.json`**，并调用 `propagateBackendSettings`（`0x9c287e0`）→ `syncContextWindow`（`0x9c34fa0`）刷新后端配置。

### 3.4 原版未生效的根源：读取链路断裂
既然 `/model` 菜单按 `Tab` + `Enter` 能够将 `"contextWindow": "900K"` 持久化写入 `~/.gemini/antigravity-cli/settings.json`，为何原版 `agy` 在下次启动或发请求时仍按 `256,000` 压缩？

原因在于读取侧函数 `store.(*Store).ContextWindow`（`0x9c34b80`）：
- 在该函数正上方 64 字节处，存在专门读取 `settings.json` 的辅助函数 **`store.(*Store).ContextWindowChoice`（`0x9c34b40`）**：
  ```text
  0000000009c34b40 <store.(*Store).ContextWindowChoice>:
   9c34b46: push   %rbp
   9c34b47: mov    %rsp,%rbp
   9c34b4a: sub    $0x10,%rsp
   9c34b4e: mov    0x10(%rax),%rcx     # rcx = s.cliSetting (*types.CliSetting)
   9c34b52: test   %rcx,%rcx
   9c34b55: je     9c34b67
   9c34b57: mov    0x70(%rcx),%rax     # rax = s.cliSetting.ContextWindow.ptr
   9c34b5b: mov    0x78(%rcx),%rbx     # rbx = s.cliSetting.ContextWindow.len
   9c34b60: call   98755e0             # backend.ParsePresetContextWindow ("256K"/"512K"/"900K")
   9c34b65: leave
   9c34b66: ret
  ```
- 然而，在 `store.(*Store).ContextWindow`（`0x9c34b80`）检查完环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 为空之后（`0x9c34ca5`），原版代码去检查了 `s.featureProvider` 是否实现内部接口 `*types.FeatureFlagReader`（`0xb7aa710`）。在外部发布版本中该类型断言分支直接跳回 `0x9c34ccf`（返回空字符串 `""`），导致 `ContextWindowChoice`（`0x9c34b40`）在整个二进制中没有任何调用者！

---

## 4. 四个核心补丁（20 字节）逐字节详解

为了将上述被阻断的链路彻底修复，`agy_context_unlock.py` 定义了 4 个必选补丁（共修改 20 个字节）与 1 个可选补丁：

### 补丁 1：`ui-selector`（修改 6 字节）
- **目标函数**：`model.SelectorModel.offersContextWindow`（`0x9e872e0`）
- **文件偏移 / 虚拟地址**：`0x9e872e0`
- **作用**：在函数入口直接令 `%eax = 1` 并返回，使 `/model` 菜单对所有模型（含原生 Flash 与网关自定义模型）开放 `[Tab] Context` 档位切换器与持久化保存。
- **指令对比**：
  ```text
  修改前 (49 89 e4 49 81 ec):
    9e872e0: 49 89 e4                mov    %rsp,%r12
    9e872e3: 49 81 ec 68 3d 00 00    sub    $0x3d68,%r12

  修改后 (b8 01 00 00 00 c3):
    9e872e0: b8 01 00 00 00          mov    $0x1,%eax
    9e872e5: c3                      ret
  ```

### 补丁 2：`store-gate`（匹配 11 字节，实际修改 5 字节）
- **目标函数**：`store.(*Store).ContextWindow`（`0x9c34b80`）
- **文件偏移 / 虚拟地址**：`0x9c34c49`（函数内偏移 `+0xc9`）
- **作用**：原版在 `0x9c34bf2..0x9c34c40` 循环比对白名单（仅含 `"Gemini 4 Argon"`），未命中时在 `0x9c34c49` 将 `%rax` 赋值为 `-1`，随后在 `0x9c34c53` 因 `jl`（小于 0）跳转至 `0x9c34c92` 直接返回空串。补丁将该处的 `mov $-1, %rax` 替换为 `xor %rax, %rax`（`%rax = 0`）加 4 个 `nop`，使所有模型均通过白名单检查。
- **指令对比**：
  ```text
  修改前 (48 c7 c0 ff ff ff ff 48 85 c0 7c):
    9c34c49: 48 c7 c0 ff ff ff ff    mov    $0xffffffffffffffff,%rax
    9c34c50: 48 85 c0                test   %rax,%rax
    9c34c53: 7c 3d                   jl     9c34c92

  修改后 (48 31 c0 90 90 90 90 48 85 c0 7c):
    9c34c49: 48 31 c0                xor    %rax,%rax
    9c34c4c: 90 90 90 90             nop ; nop ; nop ; nop
    9c34c50: 48 85 c0                test   %rax,%rax
    9c34c53: 7c 3d                   jl     9c34c92
  ```

### 补丁 3：`settings-window`（匹配 15 字节，实际修改 8 字节）
- **目标函数**：`store.(*Store).ContextWindow`（`0x9c34b80`）
- **文件偏移 / 虚拟地址**：`0x9c34ca5`（函数内偏移 `+0x125`）
- **作用**：在 `0x9c34c9a` 调用 `store.AutoCompactOverride` 检查环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 后：
  - 若环境变量非空（`test %rbx, %rbx; jne 9c34ccd`），优先返回环境变量的值；
  - 若环境变量未设置（默认情况），执行流落入 `0x9c34ca5`。补丁将原本读取 `s.featureProvider` 的指令替换为将 `Store` 指针（`0x108(%rsp)`）装入第一参数寄存器 `%rax`，直接调用上方的 `store.(*Store).ContextWindowChoice`（`0x9c34b40`）读取 `settings.json` 中的 `"contextWindow"`，随后 `leave; ret` 返回结果。
- **动态相对偏移计算**：脚本在打补丁时通过 ` Unlocker._resolve_patch_new_bytes` 动态计算 `ContextWindowChoice.va - (site_va + 13)` 的 32 位有符号相对偏移（1.5.1 中为 `0x9c34b40 - 0x9c34cb2 = -0x172`，编码为 `e8 8e fe ff ff`）。
- **指令对比**：
  ```text
  修改前 (48 8b 8c 24 08 01 00 00 48 8b 89 b8 00 00 00):
    9c34ca5: 48 8b 8c 24 08 01 00 00 mov    0x108(%rsp),%rcx
    9c34cad: 48 8b 89 b8 00 00 00    mov    0xb8(%rcx),%rcx

  修改后 (48 8b 84 24 08 01 00 00 e8 8e fe ff ff c9 c3):
    9c34ca5: 48 8b 84 24 08 01 00 00 mov    0x108(%rsp),%rax
    9c34cad: e8 8e fe ff ff          call   9c34b40 <store.(*Store).ContextWindowChoice>
    9c34cb2: c9                      leave
    9c34cb3: c3                      ret
  ```

### 补丁 4：`model-gate`（匹配 12 字节，实际修改 1 字节）
- **目标函数**：`backend.(*ServerBackend).buildCascadeConfigInternal`（`0x9888380`）
- **文件偏移 / 虚拟地址**：`0x98890a9`（修改字节位于 `0x98890ab`）
- **作用**：`buildCascadeConfigInternal` 在 `0x9889063` 获取上下文窗口字符串（如 `"900K"`），并在 `0x9889068` 调用 `ContextWindow.MaxTokenLimit()` 将其转换为整数 `900000`。但在写入 `CheckpointConfig.MaxTokenLimit`（`0x98890c9: mov %ecx, 0xc(%rax)`）前，`0x98890a4` 调用了 `proto.Equal` 比较模型对象。补丁将 `0x98890ab` 处的条件跳转 `jne`（`75`）改为无条件跳转 `jmp`（`eb`），确保任何非零窗口上限均无条件写入 `CheckpointConfig`。
- **指令对比**：
  ```text
  修改前 (84 c0 75 0a 48 8b 8c 24 b0 00 00 00):
    98890a9: 84 c0                   test   %al,%al
    98890ab: 75 0a                   jne    98890b7
    98890ad: 48 8b 8c 24 b0 00 00 00 mov    0xb0(%rsp),%rcx

  修改后 (84 c0 eb 0a 48 8b 8c 24 b0 00 00 00):
    98890a9: 84 c0                   test   %al,%al
    98890ab: eb 0a                   jmp    98890b7
    98890ad: 48 8b 8c 24 b0 00 00 00 mov    0xb0(%rsp),%rcx
  ```

### 可选补丁 5：`default-clamp`（默认不启用，通过 `--with-default-clamp` 开启）
- **目标函数**：`utils.GetCheckpointConfig`（`0x7fb0ec0`）
- **文件偏移 / 虚拟地址**：`0x7fb0fe2`（函数内偏移 `+0x122`）
- **作用**：将未配置任何窗口档位时的本地默认钳位常数 `0x3e800`（`256000`，小端字节 `00 e8 03 00`）替换为 `1048576`（`1 << 20`，小端字节 `00 00 10 00`）。由于补丁 1–4 已经打通了 `settings.json` 与 `/model` 菜单的档位控制，保留默认 `256000` 钳位可使 `/model` 中的“默认”档位维持原厂行为，故该补丁默认设为可选。

---

## 5. 命令行接口参考

```bash
# 1. 解析二进制符号表并查看各补丁位点状态（只读）
python3 agy_context_unlock.py locate --binary /usr/bin/agy

# 2. 运行离线自检，验证 5 个锚点符号地址与 20 字节精确差异（只读）
python3 agy_context_unlock.py self-test --binary /usr/bin/agy

# 3. 生成修补后的二进制文件（默认输出为 /path/to/agy.patched）
python3 agy_context_unlock.py patch --binary /usr/bin/agy --out /tmp/agy.patched

# 4. 原地修补系统二进制（自动生成 /usr/bin/agy.agy-unlock-backup 备份）
sudo python3 agy_context_unlock.py patch --binary /usr/bin/agy --in-place --yes --allow-system

# 5. 校验二进制文件中的补丁是否已生效（只读）
python3 agy_context_unlock.py verify --binary /usr/bin/agy

# 6. 生成 Arch Linux / EndeavourOS 的 Pacman 自动更新 Hook
sudo python3 agy_context_unlock.py pacman-hook \
  --script-path ~/.local/share/agy-context-unlock/agy_context_unlock.py \
  --write /etc/pacman.d/hooks/99-agy-context-unlock.hook

# 7. 从备份还原原版二进制
sudo python3 agy_context_unlock.py restore --binary /usr/bin/agy
```
