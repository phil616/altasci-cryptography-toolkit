# AltasCI根密钥生成手册

**原理：** 使用 24 个英文 BIP-39 助记词（对应 256 位熵）作为根秘密，通过 BIP-85 确定性派生 **32 字节（256 位）的 AES-256 密钥材料**。24 是**助记词数量**，32 是 **AES 密钥字节数**，不能将 `-b 32` 改成 `-b 24` 后仍称为 AES-256。

## 1. 用途及派生参数

以下是密钥派生的固定登记参数：

| K | V |
| --- | --- |
| 用途 | AES-256 |
| 根秘密 | 24 个英文 BIP-39 助记词 |
| Scheme | `bip85-standard-v1` |
| 输出格式 | BIP-85 HEX（密钥材料） |
| 字节数 | `32` |
| 索引 | `100` |
| 完整路径 | `m/83696968'/128169'/32'/100'` |
| BIP-39 Passphrase | 无（空字符串） |

**重要：** 这些参数须与初次生成时一致。若已经使用其他路径/索引派生密钥进行加密，直接修改参数会生成不同的密钥；旧版本的派生结果还可能需要 [sseed 旧版恢复步骤](https://github.com/phil616/sseed/blob/main/docs/bip85-recovery.md)。

工具：[sseed](https://github.com/phil616/sseed) · [CNB 源码](https://cnb.cool/altasci/sseed-git) · [CNB 制品库](https://cnb.cool/altasci/sseed)

## 2. 环境准备

在可信的离线工控机执行（安装依赖时可以提前完成联网准备）。建议使用已验证版本的 sseed，并记录版本及其哈希，防止未来升级影响恢复兼容性：

```bash
python3 -m venv ~/.venvs/sseed
source ~/.venvs/sseed/bin/activate
pip install sseed
sseed --help
```

或使用uv(推荐)
```bash
uv venv
source .venv/bin/activate

python -m pip install \
  --index-url https://pypi.cnb.cool/altasci/sseed/-/packages/simple \
  sseed==1.12.1

sseed --help
```

操作期间禁止终端录屏、命令输出记录、自动云同步及不可信人员接触。输出文件包含秘密材料。

## 3. 正式生成流程

### ① 建立私有工作目录

```bash
umask 077
work=$(mktemp -d)
cd "$work"
```

### ② 生成 24 个助记词

```bash
sseed gen -w 24 -l en -o wallet.txt
sseed validate -i wallet.txt
```

将助记词安全地离线备份。**任何掌握全部助记词的人都可派生出本指南中的 AES 密钥。**

### ③ Passphrase 约定

本方案**不设置 BIP-39 Passphrase**（使用空字符串）；后续派生及恢复命令均**不添加** `--prompt-passphrase`。如果未来修改该策略，必须同步修改生成、登记与恢复流程。

### ④ 生成 1-of-1 分片并演练恢复

```bash
sseed shard -i wallet.txt -g 1-of-1 -o share.txt
sseed restore share.txt -o recovered.txt
sseed validate -i recovered.txt
```

验证恢复的助记词和原文完全一致（注释或时间戳可能不同）：

```bash
python - <<'PY'
from sseed.file_operations import read_mnemonic_from_file
assert read_mnemonic_from_file("recovered.txt") == read_mnemonic_from_file("wallet.txt")
print("恢复演练通过")
PY
```

**注意：** 1-of-1 不提供真正的门限保护，单份 share 即可恢复全部秘密。应妥善保管份额，并采用物理隔离或额外的备份保护措施。

### ⑤ BIP-85 派生 AES-256 密钥材料

```bash
sseed bip85 hex -i wallet.txt -b 32 -n 100 -o app-key.hex
```

检查文件注释中的完整路径为：

```text
m/83696968'/128169'/32'/100'
```

**注意：** `app-key.hex` 是包含注释的文本文件，不是 32 字节原始二进制密钥。对接 AES 加密程序时，只使用其中的 64 位 HEX 字符表示的 32 字节密钥内容，正确解码后再使用；不要将文件全文当作 AES 密钥，也不要打印生产密钥。

### ⑥ 登记与恢复演练

保留第 1 节的派生参数，并记录所使用的 sseed 版本、备用恢复环境与加密文件格式。可再使用 `recovered.txt` 以同样参数派生第二份测试密钥，并在可信离线环境内对比二进制密钥或完成加解密演练。不要把真实助记词、原始密钥或分片提交到 Git 仓库。

### ⑦ 清理临时文件

在确认助记词/分片已安全离线备份、演练成功后：

```bash
cd ~
shred -u "$work"/wallet.txt "$work"/recovered.txt "$work"/app-key.hex
rm -rf "$work"
```

`shred` 无法保证在 SSD、写时复制文件系统、快照或虚拟化存储中彻底擦除痕迹；应使用受控的加密工作环境并管理其交换分区、快照和备份。

## 4. 从 24 个助记词/分片恢复 AES-256 密钥

### ① 创建安全工作目录

```bash
umask 077
work=$(mktemp -d)
cd "$work"
```

### ② 还原 BIP-39 助记词

如持有原有 1-of-1 份额：

```bash
sseed restore /path/to/share.txt -o recovered.txt
sseed validate -i recovered.txt
```

如直接持有 24 个原始单词，可在当前目录使用受限权限文件 `recovered.txt` 保存原文（不要把助记词写到命令行参数、聊天窗口或日志），再运行 `sseed validate -i recovered.txt`。

`validate` 只能检查格式和校验和，并不能证明助记词属于原来的密钥。

### ③ 用相同参数重新派生

```bash
sseed bip85 hex -i recovered.txt -b 32 -n 100 -o aes-key.hex
```

此处仍不使用 Passphrase，索引为 `100`，字节数为 `32`，路径仍应是 `m/83696968'/128169'/32'/100'`。

在助记词、Passphrase、派生方案和参数均一致的前提下，派生结果应与原密钥相同。

### ④ 验证恢复

通过可信的历史密钥校验值或对已知测试密文完成一次成功的认证解密来验证；仅验证助记词校验和不足以确认恢复成功。

**派生密钥 ≠ 文件加密方案。** AES-256-GCM 等实际加密仍需保存对应密文、Nonce/IV、认证标签、可能的 AAD、算法及文件格式信息，否则即使恢复了密钥也可能无法解密旧文件。

### ⑤ 清理

```bash
cd ~
shred -u "$work"/recovered.txt "$work"/aes-key.hex
rm -rf "$work"
```

同样注意 SSD / 快照等环境无法保证 `shred` 的彻底擦除效果。
