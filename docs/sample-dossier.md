# C3RB3R / `libgld` 样本档案 · Sample Dossier

> 本文件只描述样本，不分发样本本体。 This document describes the sample. It does **not** distribute the binary itself.

## 样本本体不在本仓库 · The binary is not in this repository

本仓库**不提供**可运行的勒索程序二进制。理由：分发活体勒索软件会直接造成伤害——任何人都能拿去加密他人，或改一改再作案——这也违反 GitHub 的政策。
This repository does **not** ship a runnable ransomware binary. Distributing live ransomware causes direct harm — anyone could use it to encrypt others, or re-weaponize it — and it violates GitHub policy.

安全研究员可以按下面的 SHA-256 在恶意样本平台获取同一个文件，或通过本仓库 issue 向作者联系（仅限可证明身份的安全研究用途）：
Researchers can obtain the same file by its SHA-256 from malware sample platforms, or contact the author via a repository issue (verifiable security-research use only):

- **MalwareBazaar** (abuse.ch)：按 search `sha256:802ac85d…903d`
- **VirusTotal**：按同一哈希搜索 / same hash

真正的解密突破不在二进制本身，而在**从冻结进程内存里取出会话主密钥**这个方法，已完整记录在本仓库 [README](../README.md) 和 [案例报告](case-report.md)，研究者无需拿到二进制即可复现。
The decryption breakthrough is not the binary itself but the method of **lifting the session master key from a frozen process's memory**, fully documented in the [README](../README.md) and [case report](case-report.md); it is reproducible without the binary.

## 标识 · Identifiers

| 项目 Field | 值 Value |
|---|---|
| 家族 Family | C3RB3R（Cerber 新变种，针对 Linux NAS / Cerber variant targeting Linux NAS） |
| 磁盘文件名 On-disk name | `/usr/bin/libgld`（运行后从磁盘删除，仅存于内存 / deleted after launch, memory-only） |
| 启动参数 Argv | `libgld -n 308` |
| 类型 Type | ELF x86-64，静态链接，非 PIE，UPX 3.95 加壳 / statically linked, non-PIE, UPX 3.95 packed |
| 加壳 sha256 Packed | `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d` |
| 脱壳 sha256 Unpacked | `78d06b74827429f8b9947ac5940b15fb6e6f724386dcb04dc6f7eb6dcd41d3a4` |
| 加壳大小 Packed size | 462,312 字节 bytes |
| 加密后缀 Extension | `.L0CK3D` |
| 勒索信 Ransom note | 每个目录一份 `read-me3.txt` / `read-me3.txt` in every directory |
| 配套后门 Paired backdoor | 反弹 shell，sha256 `fb42552d86d4284900c0fa048d07108dab7dc72e05421a8e9cef943dff0fd61b`（两进程同一文件 / two processes, one file），C2 `208.87.128.140:4001` |

## 加密结构 · Crypto

- **文件加密 File encryption**：ChaCha8，32 字节 key + 8 字节 nonce + 64 位计数器，每文件一把随机 key，每次调用上限 5 MiB（末块不足一块也占一个计数步）。 ChaCha8, 32B key + 8B nonce + 64-bit counter, a random key per file, ≤5 MiB per call (a short final block still consumes one counter step).
- **key 保护 Key protection**：每文件 key 用会话主密钥 AES-256-CBC 包裹，存在文件尾前 48 字节（IV16 + key32）。会话主密钥只在加密进程内存里，全局指针 `0x5427f8`（VA 5515256）。 Each per-file key is AES-256-CBC-wrapped by a session master key in the 48 bytes before the footer (IV16 + key32); the master lives only in memory, global pointer `0x5427f8` (VA 5515256).
- **运行模式字节 Mode byte**：`0x53fc8c`（VA 5504140）；`0x20` = 真加密 real，`0x21` = 诱饵 decoy。
- **随机数 RNG**：wolfSSL `wc_GenerateSeed` → `/dev/urandom`，上层 Hash_DRBG，设计上不可从当前状态反推历史 key ⇒ 从随机数入手解密不可行。 Hash_DRBG on top; past keys cannot be derived from current state, so attacking the RNG is not viable.
- **字符串 Strings**：运行时解码（形如 `x*0x6d+0x1d mod 127`）。 Decoded at runtime.

## 文件尾布局（588 字节）· Footer layout (588 bytes)

| 偏移 Offset | 长度 Len | 含义 Meaning |
|---|---|---|
| 0 | 48 | AES-CBC 包裹的记录 = `file_key32 + nonce8 + nonce8`（nonce 重复一遍作校验）。 AES-CBC-wrapped record (nonce duplicated as a check). |
| 568 | 4 | 会话标记（本案 `883c0309`，每次运行不同）。 session marker (`883c0309` here; differs per run). |
| 572 | 1 | 文件模式 file mode：`0x24` 全文件 full / `0x25` 分段 partial / `0x26` 前 1 MiB first 1 MiB |
| 573 | 1 | 分段参数（百分比，仅 `0x25` 用）。 partial parameter (percent; only for `0x25`). |
| 574 | 1 | crypto 模式 crypto mode：`0x20` 真加密 real / `0x21` 诱饵 decoy |
| 580 | 8 | uint64 原始文件大小（小端）。 original file size (little-endian). |

## 分段参数（模式 0x25）· Partial factors (mode 0x25)

百分比 → 每段加密的块因子。本案抽样 400 个文件的模式分布：分段 56%、前 1 MiB 31%、全文件 13%。
Percent → block factor per encrypted segment. Mode distribution across 400 sampled files: partial 56%, first 1 MiB 31%, full 13%.

```
PF = {10:4, 15:5, 20:7, 25:9, 30:10, 35:12, 40:14, 50:10, 60:20, 70:23, 80:27}
# 段长 segment length = (size // 100) * PF[pct]；段数 count = 50% 时 5 段 else 3
```

## 不能跨受害者解密 · Not reusable across victims

每次运行生成一把新的会话主密钥，不同受害者（乃至同一台机器的不同运行）的会话标记都不同。**只能用自己那台冻结进程内存里的主密钥。**本仓库的工具对任何其它受害者都不是现成的解密器，只是方法与地址的参考。
Each run derives a new session master key; the marker differs between victims (and even between runs on one machine). **Only the master from your own frozen process's memory works.** The tools here are not a turnkey decryptor for any other victim — they are a reference for method and addresses.
