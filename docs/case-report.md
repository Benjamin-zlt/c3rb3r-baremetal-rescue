# 案例报告 · Case Report：物理机 DSM 上的 C3RB3R 加密与完整恢复 / C3RB3R encryption and full recovery on bare-metal DSM

> English first, 中文在后。 | 中文版见下方 [中文](#中文).

---

## English

All internal addresses, accounts, share names, and business directories are redacted. Times are NAS local time (UTC+8).

### Environment

- Xpenology DS918+, DSM 7.2, x86_64, Intel i3-10100T, 16GB RAM, btrfs
- The main share had NoCOW enabled (`chattr +C`); encryption overwrote in place ⇒ btrfs snapshot / old-root recovery not viable
- The NAS had public IPv6 directly; the router had no IPv6 firewall

### Timeline

| Time | Event |
|---|---|
| 37 days before | A reverse shell to `208.87.128.140:4001` began persisting (root) |
| Day D 03:05 | Encryption starts. `/usr/bin/libgld -n 308`, 8 concurrent file handles, binary already deleted from disk |
| Day D 03:05:33–56 | The first thing encrypted was a Docker app's data directory (config, `.env`, credential files) |
| Day D+1 10:55 | Discovered while the process was still running. `kill -STOP` to freeze; dumped `/proc/PID/exe`, maps, 2GB writable memory; killed the reverse shell, iptables-blocked the C2, closed telnet |
| Day D+1 17:20 | Session master key obtained and verified |
| Day D+1 17:32 | Local bulk decryption on the NAS begins |

### Entry point (high confidence)

- Public IPv6 directly exposed telnet 23 (root login allowed), SSH 22, DSM 5000/5001
- No direct evidence of a DSM exploit; exposed telnet root is sufficient on its own. The first case points to CVE-2024-10441 (environment-variable injection in a DSM login plugin); both paths are worth checking

### Impact

- Main share ~3.88M files, 84,504 encrypted (~2.2%), ~942GB. Encryption was not finished when it was frozen
- Another Docker app directory: 10,135 of 184K files encrypted, ~10.4GB
- 400 sampled encrypted files all share one session marker ⇒ one master key

### Recovery

1. Dumped the frozen process's rw regions with `dump_process_memory.py` (2.0GB here); exe sha256 identical to the first case
2. Mode byte `0x53fc8c` = `0x20` (real encryption); global pointer `0x5427f8` → the 48-byte master key on the heap
3. Verified with "encrypted file + a good copy from elsewhere in the share": 40 random pairs, 39 SHA-256-identical, covering all three modes. The only mismatch was `Thumbs.db`, due to a wrong pairing: same size but not the same file
4. Written next to the originals on the NAS: after 15 pilot files matched the originals, started in full, ~110MB/s, main share and Docker data in parallel, zero failures

### Lessons

- **Freeze, don't kill; don't reboot.** This is the one action that kept the key alive. Recovery here was possible only because the process was still running when found and was `SIGSTOP`ped rather than killed
- The earlier analysis wrongly concluded "random per-file key, attacker's private key required," because it only looked at the public-key-wrapped blob and the RNG. The right move is to first check **whether memory holds a symmetric key that unwraps the 48-byte footer**
- Don't give a NAS public IPv6 without a firewall; don't run telnet
- NoCOW on an important share disables all snapshot / copy-on-write recovery

### IOC

| Type | Value |
|---|---|
| Encryptor sha256 (packed) | `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d` |
| Encryptor sha256 (unpacked, from case 1) | `78d06b74827429f8b9947ac5940b15fb6e6f724386dcb04dc6f7eb6dcd41d3a4` |
| Process path | `/usr/bin/libgld` (deleted after launch), argv `libgld -n 308` |
| C2 | `208.87.128.140:4001` (TCP, reverse shell) |
| Extension / note | `.L0CK3D` / `read-me3.txt` |
| Session marker here | `883c0309` (differs per run; only distinguishes sessions) |

---

## 中文

所有内网地址、账号、共享名和业务目录均已隐去。时间为 NAS 本地时间（UTC+8）。

### 环境

- 黑群晖 DS918+，DSM 7.2，x86_64，Intel i3-10100T，16GB 内存，btrfs
- 主共享开启了 NoCOW（`chattr +C`），加密是原地覆盖 ⇒ btrfs 快照/旧树根恢复不可行
- NAS 直接拿到了公网 IPv6，路由器没有开 IPv6 防火墙

### 时间线

| 时间 | 事件 |
|---|---|
| 加密前 37 天 | 反弹 shell 连向 `208.87.128.140:4001` 开始驻留（root） |
| D 日 03:05 | 加密开始。`/usr/bin/libgld -n 308`，8 个并发文件句柄，二进制已从磁盘删除 |
| D 日 03:05:33–56 | 最先被加密的是一个 Docker 应用的数据目录（配置、`.env`、凭据文件） |
| D+1 日 10:55 | 发现时进程仍在运行。`kill -STOP` 冻结，导出 `/proc/PID/exe`、maps、2GB 可写内存；杀掉反弹 shell，iptables 封 C2，关 telnet |
| D+1 日 17:20 | 取得会话主密钥，验证通过 |
| D+1 日 17:32 | NAS 本地批量解密开始 |

### 入口（高可信）

- 公网 IPv6 直接暴露了 telnet 23（root 可登录）、SSH 22、DSM 5000/5001
- 未见 DSM 漏洞利用的直接证据；telnet root 暴露本身就足够解释。第一个案例指向 CVE-2024-10441（DSM 登录插件环境变量注入），两条路径都值得排查

### 损失面

- 主共享约 388 万个文件，被加密 84,504 个（约 2.2%），约 942GB。加密在被冻结时还没跑完
- 另一个 Docker 应用目录 18.4 万个文件里被加密 10,135 个，约 10.4GB
- 抽样 400 个加密文件，全部同一个会话标记 ⇒ 同一把主密钥

### 恢复

1. `dump_process_memory.py` 方式导出冻结进程的 rw 区域（本案 2.0GB），exe sha256 与第一个案例完全一致
2. 运行模式字节 `0x53fc8c` = `0x20`（真加密）；全局指针 `0x5427f8` → 堆上 48 字节主密钥
3. 用「被加密文件 + 共享里别处的完好副本」验证：随机 40 对，39 对 SHA-256 一致，覆盖三种模式。唯一不一致的是 `Thumbs.db`，原因是配对选错了：同尺寸，但不是同一个文件
4. 在 NAS 本地写到原文件旁边：15 个试点文件与原件全一致后全量启动，约 110MB/s，主共享和 Docker 数据同时进行，零失败

### 教训

- **冻结，不要杀；不要重启。**这是唯一让密钥活下来的操作。本案能恢复，完全是因为发现时进程还在、并且被 `SIGSTOP` 而不是 `kill`
- 之前分析错误地得出「每文件随机 key、需攻击者私钥」，原因是只看了公钥包裹区和 RNG。正确做法是先确认**内存里有没有能解开文件尾 48 字节的对称密钥**
- 不要让 NAS 拿公网 IPv6 却不开防火墙；不要开 telnet
- 重要共享开 NoCOW 会让快照/写时复制恢复全部失效

### IOC

| 类型 | 值 |
|---|---|
| 加密器 sha256（packed） | `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d` |
| 加密器 sha256（unpacked，来自案例一） | `78d06b74827429f8b9947ac5940b15fb6e6f724386dcb04dc6f7eb6dcd41d3a4` |
| 进程路径 | `/usr/bin/libgld`（运行后删除），命令行 `libgld -n 308` |
| C2 | `208.87.128.140:4001`（TCP，反弹 shell） |
| 扩展名 / 勒索信 | `.L0CK3D` / `read-me3.txt` |
| 本案会话标记 | `883c0309`（每次运行不同，仅用于区分会话） |
