# C3RB3R (.L0CK3D) 群晖 / 黑群晖 实机解密案例 · Bare-metal Synology Recovery Case

**C3RB3R 勒索病毒（`.L0CK3D`，`read-me3.txt`）打在物理机群晖 DSM 上：没付赎金，靠冻结加密进程、从内存里读出会话密钥，全量恢复。**
**C3RB3R ransomware (.L0CK3D, `read-me3.txt`) on bare-metal Synology DSM: full recovery without paying, by freezing the encryptor and reading its session key from process memory.**

这是继 [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue) 之后**第二个独立受害者的成功案例**。第一个案例跑在 PVE 虚拟机里，靠整机 RAM 镜像拿到密钥。这个案例跑在**物理机（黑群晖 DS918+，DSM 7.2）**上，没有虚拟化层，靠的是**在加密进程还活着的时候 `kill -STOP` 冻结它，再从 `/proc/PID/mem` 导出内存**。
This is the **second independent victim's successful case** after [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue). The first ran inside a PVE VM and recovered the key from a whole-VM RAM image. This one ran on **bare metal (a Xpenology DS918+, DSM 7.2)** with no virtualization layer, relying on **`kill -STOP` to freeze the encryptor while still alive, then dumping `/proc/PID/mem`**.

结果：8.45 万个被加密文件（约 940GB），**全部用一把从内存里取出的会话密钥解开**，抽样验证与原件逐字节一致。
Result: 84,500 encrypted files (~940GB), **all decrypted with a single session key lifted from memory**; spot checks are byte-identical to the originals.

> 如果你刚发现文件变成 `.L0CK3D`，先看下面「第一时间该做什么」。**不要重启 NAS，不要 kill 加密进程。**
> If you have just found your files turned into `.L0CK3D`, read **What to do right now** below first. **Do not reboot the NAS. Do not kill the encryptor process.**

## 第一时间该做什么 · What to do right now

1. **找到加密进程，冻结它，不要杀掉。 / Find the encryptor, freeze it, do not kill it.**
   ```sh
   ls -l /proc/*/exe 2>/dev/null | grep deleted     # 本案是 /usr/bin/libgld (deleted) / here it was libgld
   kill -STOP <PID>                                 # 冻结 freeze. kill -9 / 重启 reboot = 密钥永久丢失 key lost forever
   grep State /proc/<PID>/status                    # 确认是 confirm it is T (stopped)
   ```
2. **立刻导出内存和样本（需要 root）/ Dump memory and the sample immediately (needs root)：**
   `python3 tools/dump_process_memory.py <PID> /volume1/<有空间的共享 a share with space>/ir`
3. **切断入口 / Cut off the entry point**：路由器 IPv6 防火墙、关 telnet/SSH 对外、杀掉反弹 shell。导出完成之前，不要重启。 Router IPv6 firewall, close telnet/SSH to the internet, kill the reverse shell. Do not reboot until the dump is done.
4. 核对 `ir/exe.bin` 的 sha256。如果是 `802ac85d…903d`，就可以直接用本仓库；如果不是，需要重新逆向地址（见 soimy 仓库的方法）。 Check the sha256 of `ir/exe.bin`. If it is `802ac85d…903d`, use this repo directly; if not, the addresses must be re-reversed (see soimy's method).

## 恢复步骤 · Recovery steps

```sh
# 1. 取出 48 字节会话主密钥（IV16 + AES-256 key32），只用标准库，DSM 自带 python3 即可
#    Extract the 48-byte session master key (IV16 + AES-256 key32). Standard library only; DSM's built-in python3 is enough.
python3 tools/extract_master.py ir/ master.bin

# 2. 准备 numpy（DSM 没有 pip：在别的电脑上下载官方 wheel，拷过去直接解压）
#    Prepare numpy (DSM has no pip: download the official wheel on another PC, copy it over, unzip in place)
#    pip download numpy==1.24.4 --python-version 3.8 --platform manylinux2014_x86_64 --only-binary=:all: --no-deps
python3 -m zipfile -e numpy-1.24.4-*.whl tools/lib/

# 3. 先用「加密文件 + 别处的完好副本」验证密钥，三种加密模式都要覆盖
#    Verify the key first with "encrypted file + a good copy from elsewhere"; cover all three modes
python3 tools/verify_pairs.py master.bin pairs.tsv

# 4. 会话标记 = 任意 .L0CK3D 文件倒数第 20 字节起的 4 字节
#    Session marker = 4 bytes starting at the 20th-from-last byte of any .L0CK3D file
tail -c 20 some.jpg.L0CK3D | head -c 4 | od -An -tx1

# 5. 在 NAS 本地批量解密，不走网络；原 .L0CK3D 保留，不覆盖任何已有文件
#    Bulk-decrypt locally on the NAS, no network; the original .L0CK3D is kept, nothing existing is overwritten
cd /volume1/SHARE && find . -name '*.L0CK3D' | sed 's|^\./||' > /volume1/rescue/files.lst
setsid nohup python3 tools/bulk_decrypt_local.py --root /volume1/SHARE \
    --list /volume1/rescue/files.lst --master master.bin --marker <标记 marker> \
    --state /volume1/rescue > /volume1/rescue/run.out 2>&1 < /dev/null &
```

## 关键结论 · Key findings

| 项目 Item | 内容 Content |
|---|---|
| 样本 Sample | `libgld`，ELF x86-64 静态链接，UPX 3.95 加壳；packed sha256 `802ac85d…903d`（与第一个案例同一文件）。 ELF x86-64, static, UPX 3.95 packed; **same file** as the first case |
| 文件加密 File encryption | ChaCha8，32B key + 8B nonce + 64 位计数器，每文件随机 key。 ChaCha8, 32B key + 8B nonce + 64-bit counter, a random key per file |
| key 保护 Key protection | 每文件 key 用会话主密钥（AES-256-CBC）包裹，存在文件尾前 48 字节；主密钥只在进程内存里，全局指针 `0x5427f8`。 wrapped by a session master key (AES-256-CBC) in the 48 bytes before the footer; the master lives only in memory, global pointer `0x5427f8` |
| 文件尾 Footer | 588 字节；568 会话标记，572 模式（0x24 全文件 / 0x25 分段 / 0x26 前 1MiB），574 crypto 模式（0x20 真加密 / 0x21 诱饵），580 原始大小。 588 bytes; 568 marker, 572 mode, 574 crypto mode, 580 original size |
| 本案模式分布 Mode distribution | 分段 56%、前 1MiB 31%、全文件 13%（抽样 400）。 partial 56%, first 1MiB 31%, full 13% (400 sampled) |
| 能否跨受害者 Reusable? | **不能 No。**每次运行一把新会话密钥，标记各不相同；只能用自己进程内存里的那把。 Each run uses a new key with a different marker; only the one in your own process memory works |

## 为什么之前以为解不开 · Why it looked unbreakable at first

文件尾里还有一段 304 字节的公钥包裹数据，key 的随机数来源也是 wolfSSL 的 Hash_DRBG（`/dev/urandom` 播种），看起来像是「没有攻击者私钥就无解」。实际上程序在同一个运行会话里一直把 AES 主密钥留在内存里，用来包裹每个文件的 key。**只要进程没死，主密钥就在。**这就是为什么「冻结、不杀、不重启」是整个恢复的前提。
The footer also holds a 304-byte public-key-wrapped blob, and the key's RNG is wolfSSL's Hash_DRBG (seeded from `/dev/urandom`), which looks like "no decryption without the attacker's private key." In reality the program keeps the AES master key in memory for the whole run, using it to wrap every file's key. **As long as the process is alive, the master is there.** That is why "freeze, don't kill, don't reboot" is the premise of the entire recovery.

## 和第一个案例的区别 · Differences from the first case

| | soimy/c3rb3r-rescue | 本案 This case |
|---|---|---|
| 平台 Platform | PVE 虚拟机里的 DSM / DSM inside a PVE VM | 物理机黑群晖 / bare-metal Xpenology |
| 内存来源 Memory source | QEMU 整机 RAM（16GB），要做页表翻译 / whole-VM RAM, needs page-table translation | 冻结进程的 `/proc/PID/mem`（2GB 可写区），直接按虚拟地址读 / frozen process's mem, read by virtual address |
| 解密位置 Location | 独立副本上离线解密 / offline on a separate copy | NAS 本地原位解密（写到原文件旁边），不搬数据 / in place on the NAS, no data moved |
| 速度 Speed | — | i3-10100T 单进程约 110MB/s，940GB 约 2.5 小时 / ~110MB/s, ~2.5h for 940GB |

## 目录 · Layout

- `tools/c3dec.py`：文件格式与解密核心（ChaCha8 + AES-CBC 解包 + 分段规则）。 File format and decryption core.
- `tools/dump_process_memory.py`：导出冻结进程的样本和可写内存。 Dump the frozen process's sample and writable memory.
- `tools/extract_master.py`：按样本 profile 从内存镜像取会话主密钥。 Lift the session master key from the memory image.
- `tools/verify_pairs.py`：用已知原件验证密钥。 Verify the key against known originals.
- `tools/bulk_decrypt_local.py`：NAS 本地批量解密，可断点续跑。 Bulk local decryption on the NAS, resumable.
- `profiles/libgld-802ac85d.json`：样本地址。 Sample addresses.
- `tests/`：不依赖样本和真实密钥的自测（ChaCha 核心对照标准 ChaCha20、三种模式往返、错误密钥拒绝）。 Self-tests that need no sample and no real key.
- `docs/case-report.md`：本案经过、入口和 IOC。 The incident, entry point, and IOCs.
- `docs/sample-dossier.md`：样本档案（中英文）——哈希、加密结构、文件尾布局、分段参数，以及如何按哈希在 MalwareBazaar 获取样本。 Sample dossier — hashes, crypto layout, footer, partial factors, and how to obtain the sample by hash from MalwareBazaar.

本仓库**不包含**恶意样本、受害者数据或任何真实密钥。
This repo contains **no** malware sample, no victim data, and no real key.

## 致谢 · Credits

格式、地址和「会话主密钥在内存里」的关键发现来自 [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue)。本仓库是在第二个受害者身上的独立复现，以及针对物理机 DSM 的流程补充。
The format, the addresses, and the key insight that "the session master key is in memory" come from [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue). This repo is an independent reproduction on a second victim, plus a process adaptation for bare-metal DSM.
