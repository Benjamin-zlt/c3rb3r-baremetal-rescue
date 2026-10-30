# 案例报告 · Case Report：物理机 DSM 上的 C3RB3R 加密与完整恢复 / C3RB3R encryption and full recovery on bare-metal DSM

所有内网地址、账号、共享名和业务目录均已隐去。时间为 NAS 本地时间（UTC+8）。
All internal addresses, accounts, share names, and business directories are redacted. Times are NAS local time (UTC+8).

## 环境 · Environment

- 黑群晖 DS918+，DSM 7.2，x86_64，Intel i3-10100T，16GB 内存，btrfs。 Xpenology DS918+, DSM 7.2, x86_64, i3-10100T, 16GB RAM, btrfs.
- 主共享开启了 NoCOW（`chattr +C`），加密是原地覆盖 ⇒ btrfs 快照/旧树根恢复不可行。 The main share had NoCOW; encryption overwrote in place ⇒ btrfs snapshot / old-root recovery not viable.
- NAS 直接拿到了公网 IPv6，路由器没有开 IPv6 防火墙。 The NAS had public IPv6 directly; the router had no IPv6 firewall.

## 时间线 · Timeline

| 时间 Time | 事件 Event |
|---|---|
| 加密前 37 天 37 days before | 反弹 shell 连向 `208.87.128.140:4001` 开始驻留（root）。 A reverse shell to `208.87.128.140:4001` began persisting (root). |
| D 日 03:05 Day D 03:05 | 加密开始。`/usr/bin/libgld -n 308`，8 个并发文件句柄，二进制已从磁盘删除。 Encryption starts; 8 concurrent handles, binary already deleted from disk. |
| D 日 03:05:33–56 | 最先被加密的是一个 Docker 应用的数据目录（配置、`.env`、凭据文件）。 First encrypted: a Docker app's data directory (config, `.env`, credentials). |
| D+1 日 10:55 Day D+1 10:55 | 发现时进程仍在运行。`kill -STOP` 冻结，导出 exe、maps、2GB 可写内存；杀反弹 shell，iptables 封 C2，关 telnet。 Found still running. `kill -STOP`; dumped exe/maps/2GB memory; killed reverse shell, blocked C2, closed telnet. |
| D+1 日 17:20 | 取得会话主密钥，验证通过。 Session master key obtained and verified. |
| D+1 日 17:32 | NAS 本地批量解密开始。 Local bulk decryption begins. |

## 入口（高可信）· Entry point (high confidence)

- 公网 IPv6 直接暴露了 telnet 23（root 可登录）、SSH 22、DSM 5000/5001。 Public IPv6 directly exposed telnet 23 (root login), SSH 22, DSM 5000/5001.
- 未见 DSM 漏洞利用的直接证据；telnet root 暴露本身就足够解释。第一个案例指向 CVE-2024-10441（DSM 登录插件环境变量注入），两条路径都值得排查。 No direct evidence of a DSM exploit; exposed telnet root is sufficient on its own. The first case points to CVE-2024-10441; both paths are worth checking.

## 损失面 · Impact

- 主共享约 388 万个文件，被加密 84,504 个（约 2.2%），约 942GB。加密在被冻结时还没跑完。 Main share ~3.88M files, 84,504 encrypted (~2.2%), ~942GB; not finished when frozen.
- 另一个 Docker 应用目录 18.4 万个文件里被加密 10,135 个，约 10.4GB。 Another Docker app directory: 10,135 of 184K files encrypted, ~10.4GB.
- 抽样 400 个加密文件，全部同一个会话标记 ⇒ 同一把主密钥。 400 sampled files all share one marker ⇒ one master key.

## 恢复 · Recovery

1. `dump_process_memory.py` 导出冻结进程的 rw 区域（本案 2.0GB），exe sha256 与第一个案例完全一致。 Dumped the frozen process's rw regions (2.0GB); exe sha256 identical to the first case.
2. 运行模式字节 `0x53fc8c` = `0x20`（真加密）；全局指针 `0x5427f8` → 堆上 48 字节主密钥。 Mode byte `0x53fc8c` = `0x20` (real); global pointer `0x5427f8` → the 48-byte master key on the heap.
3. 用「被加密文件 + 共享里别处的完好副本」验证：随机 40 对，39 对 SHA-256 一致，覆盖三种模式。唯一不一致的是 `Thumbs.db`，配对选错（同尺寸不同文件）。 Verified with encrypted + good-copy pairs: 40 random, 39 SHA-256-identical across all three modes; the only mismatch was a wrongly paired `Thumbs.db` (same size, different file).
4. 在 NAS 本地写到原文件旁边：15 个试点文件与原件全一致后全量启动，约 110MB/s，主共享和 Docker 数据同时进行，零失败。 Written next to the originals; after 15 matching pilots, ran in full at ~110MB/s, main share and Docker data in parallel, zero failures.

## 教训 · Lessons

- **冻结，不要杀；不要重启。**这是唯一让密钥活下来的操作。本案能恢复，完全是因为发现时进程还在、并且被 `SIGSTOP` 而不是 `kill`。 **Freeze, don't kill; don't reboot.** The one action that kept the key alive; recovery was possible only because the process was still running and was `SIGSTOP`ped rather than killed.
- 之前分析错误地得出「每文件随机 key、需攻击者私钥」，原因是只看了公钥包裹区和 RNG。正确做法是先确认内存里有没有能解开文件尾 48 字节的对称密钥。 The earlier "random per-file key, private key required" conclusion came from only looking at the public-key blob and RNG; first check whether memory holds a symmetric key that unwraps the 48-byte footer.
- 不要让 NAS 拿公网 IPv6 却不开防火墙；不要开 telnet。 Don't give a NAS public IPv6 without a firewall; don't run telnet.
- 重要共享开 NoCOW 会让快照/写时复制恢复全部失效。 NoCOW on an important share disables all snapshot / copy-on-write recovery.

## IOC

| 类型 Type | 值 Value |
|---|---|
| 加密器 sha256（packed）Encryptor sha256 (packed) | `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d` |
| 加密器 sha256（unpacked，来自案例一）(unpacked, from case 1) | `78d06b74827429f8b9947ac5940b15fb6e6f724386dcb04dc6f7eb6dcd41d3a4` |
| 进程路径 Process path | `/usr/bin/libgld`（运行后删除 deleted after launch），argv `libgld -n 308` |
| C2 | `208.87.128.140:4001`（TCP，反弹 shell / reverse shell） |
| 扩展名 / 勒索信 Extension / note | `.L0CK3D` / `read-me3.txt` |
| 本案会话标记 Session marker here | `883c0309`（每次运行不同，仅用于区分会话 / differs per run, only distinguishes sessions） |
