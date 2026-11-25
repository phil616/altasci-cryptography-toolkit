# AltasCI根密钥生成手册

> U2FsdGVkX1/ntjVSzOhWHbAJQKQL7z+ik4NUzsdNT1cE6w6gHuWefTEEiYIwvVDSM6lvC8S5YgM2wOEkQqd0QQI/ubT7Bc11pO3wDSO62k0=

**原理：** 使用 24 个英文 BIP-39 助记词（对应 256 位熵）作为根秘密，通过 BIP-85 确定性派生 **32 字节（256 位）的 AES-256 密钥材料**。24 是**助记词数量**，32 是 **AES 密钥字节数**，不能将 `-b 32` 改成 `-b 24` 后仍称为 AES-256。

**区分三个标准：** BIP-39 表示根秘密；BIP-85 确定性派生密钥；SLIP-39 仅用于可选的秘密共享备份与恢复。直接持有原始 24 词 BIP-39 助记词时，不需要执行 `sseed restore`，也不需要生成 SLIP-39 分片。

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

或使用 uv（推荐）：

```bash
uv venv
source .venv/bin/activate

python -m pip install \
  --index-url https://pypi.cnb.cool/altasci/sseed/-/packages/simple \
  sseed==1.12.1

sseed --help
```

操作期间禁止终端录屏、命令输出记录、自动云同步及不可信人员接触。输出文件包含秘密材料。工作目录应位于受控的加密存储或合适的 RAM 文件系统上；`/tmp` 不一定是 tmpfs，可用 `findmnt -T "$PWD"` 确认当前目录的文件系统。即使使用 tmpfs，也须管理交换空间、休眠及转储风险。

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

### ④ BIP-85 派生 AES-256 密钥材料

```bash
sseed bip85 hex -i wallet.txt -b 32 -n 100 -o app-key.hex
```

检查文件注释中的完整路径为：

```text
m/83696968'/128169'/32'/100'
```

**注意：** `app-key.hex` 是包含注释的文本文件，不是 32 字节原始二进制密钥。对接 AES 加密程序时，只使用其中的 64 位 HEX 字符表示的 32 字节密钥内容，正确解码后再使用；不要将文件全文当作 AES 密钥，也不要打印生产密钥。

### ⑤ 登记与恢复演练

保留第 1 节的派生参数，并记录所使用的 sseed 版本、备用恢复环境与加密文件格式。从离线备份重新导入原始 24 词助记词，保存为权限受限的 `recovered.txt`，按照第 4 节验证和派生，确认与首次派生的密钥一致或完成认证加解密演练。如需多人共同恢复，可选用第 5 节的 SLIP-39 门限备份。不要把真实助记词、原始密钥或分片提交到 Git 仓库。

### ⑥ 清理临时文件

在确认根秘密已安全离线备份、演练成功且不再需要工作目录中的密钥后：

```bash
cd ~
find "$work" -maxdepth 1 -type f -exec shred -u -- {} +
rm -rf "$work"
```

`shred` 无法保证在 SSD、写时复制文件系统、快照或虚拟化存储中彻底擦除痕迹；应使用受控的加密工作环境并管理其交换分区、快照和备份。

## 4. 恢复 AES-256 密钥（优先使用原始 BIP-39 助记词）

### ① 创建安全工作目录

```bash
umask 077
work=$(mktemp -d)
cd "$work"
```

### ② 识别备份文件类型

不要仅根据文件名判断格式。历史备份可能命名为 `share.txt`，但实际保存的是 BIP-39 助记词。对于只包含一份助记词及可选的 # 注释行的文本文件，以下命令只统计词数，不显示秘密内容：

```bash
awk '!/^[[:space:]]*#/ {n+=NF} END {print n+0}' /path/to/share.txt
```

| 备份类型（本手册的 256 位秘密） | 词数 | 恢复方式 |
| --- | --- | --- |
| 英文 BIP-39 原始助记词 | 24 | 验证后直接 BIP-85 派生 |
| SLIP-39 恢复份额 | 每份 33 | 满足门限后执行 `sseed restore`，再 BIP-85 派生 |

词数仅用于初步识别，不代表有效性。其他词数、含额外文件头或包含多个份额的文件，应根据实际备份格式及生成记录判断，不得自行删改单词。

### ③ 路径 A：直接使用 24 词 BIP-39 助记词（推荐）

将原始备份复制到私有工作目录（不修改原备份），并限制权限：

```bash
install -m 600 /path/to/share.txt wallet.txt
sseed validate -i wallet.txt
```

如果备份已经在当前私有工作目录中，也可以直接使用原文件名：

```bash
sseed validate -i share.txt
sseed bip85 hex -i share.txt -b 32 -n 100 -o aes-key.hex
```

仅在确认验证通过后执行派生。若已复制为 `wallet.txt`，使用：

```bash
sseed bip85 hex -i wallet.txt -b 32 -n 100 -o aes-key.hex
```

这一路径完全不使用 `sseed restore`。

### ④ 路径 B：从真正的 SLIP-39 份额恢复（可选）

如果持有旧版手册生成的 1-of-1 SLIP-39 份额：

```bash
sseed restore /path/to/share.txt -o recovered.txt
sseed validate -i recovered.txt
```

如果采用多人门限备份，需要提供满足原始门限配置的不同有效份额；具体多份额输入方式以已登记版本的 `sseed restore --help` 为准。若分片时使用了 SLIP-39 Passphrase，必须按原配置恢复；它与 BIP-39 Passphrase 是不同的参数。

确认恢复的 BIP-39 助记词验证通过后：

```bash
sseed bip85 hex -i recovered.txt -b 32 -n 100 -o aes-key.hex
```

此处仍不使用 Passphrase，索引为 `100`，字节数为 `32`，路径仍应是 `m/83696968'/128169'/32'/100'`。

在助记词、Passphrase、派生方案和参数均一致的前提下，派生结果应与原密钥相同。

### ⑤ 检查输出格式及验证恢复

`aes-key.hex` 含注释，不是原始二进制密钥。如应用需要纯 HEX 或原始 32 字节密钥，在私有工作目录内执行（需要 `xxd`）：

```bash
(
    set -eu
    umask 077
    [ "$(grep -Ec '^[0-9a-fA-F]{64}$' aes-key.hex)" -eq 1 ]
    grep -E '^[0-9a-fA-F]{64}$' aes-key.hex > aes-key.raw.hex
    xxd -r -p aes-key.raw.hex > aes-key.bin
    [ "$(wc -c < aes-key.bin)" -eq 32 ]
    printf '密钥格式检查通过（32 字节）\n'
)
```

如果命令失败，不要继续使用输出文件；检查工具版本及输出格式。长度检查只能证明格式正确，不能证明密钥是原密钥。

通过可信的历史密钥校验值或对已知测试密文完成一次成功的认证解密来验证；仅验证助记词校验和不足以确认恢复成功。

**派生密钥 ≠ 文件加密方案。** AES-256-GCM 等实际加密仍需保存对应密文、Nonce/IV、认证标签、可能的 AAD、算法及文件格式信息，否则即使恢复了密钥也可能无法解密旧文件。

### ⑥ 清理

在确认原始备份及需要保留的恢复结果已经安全保存，并且工作目录不再需要后，清理临时文件：

```bash
cd ~
find "$work" -maxdepth 1 -type f -exec shred -u -- {} +
rm -rf "$work"
```

同样注意 SSD / 快照等环境无法保证 `shred` 的彻底擦除效果。

## 5. 可选：SLIP-39 门限备份

SLIP-39 在 sseed 中备份的是 BIP-39 助记词对应的原始熵，不是 BIP-85 派生后的 AES 密钥。只有需要多人共同恢复或门限容灾时才必须考虑这一环节；普通离线备份可以直接保管原始 24 词。

- 1-of-1：单份即可恢复全部秘密，不提供门限保护；仅用于兼容既有备份或演练。
- 2-of-3 / 3-of-5：分别要求 2 / 3 个不同份额才可恢复。按实际职责分离和容灾要求选择，并将份额分别保管。

旧版 1-of-1 备份生成及恢复演练：

```bash
sseed shard -i wallet.txt -g 1-of-1 -o slip39-share.txt
sseed restore slip39-share.txt -o recovered.txt
sseed validate -i recovered.txt
```

对于门限配置，可使用 `sseed shard -i wallet.txt -g 3-of-5 -o slip39-share.txt`，根据实际版本的输出格式分别保存不同份额，并使用足够份额演练恢复。不要将整组份额交给同一个保管人。

在可信离线环境中比对恢复后的原始助记词：

```bash
python - <<'PY'
from sseed.file_operations import read_mnemonic_from_file
assert read_mnemonic_from_file("recovered.txt") == read_mnemonic_from_file("wallet.txt")
print("恢复演练通过")
PY
```

如果完整的 BIP-39 助记词仍由单人保管，门限保护可被绕过；只有在完成备份及恢复演练后，才按既定制度清理完整助记词及临时密钥。

## 6. 常见故障

### restore 报 Invalid mnemonic word

可能是误将 BIP-39 助记词当成 SLIP-39 份额输入，也可能是份额损坏或输入格式不正确。先检查词数，不要随意替换报错中的单词。如果文件包含 24 个英文 BIP-39 助记词，且 `sseed validate -i share.txt` 的 Format、Language、Checksum 检查均通过，按第 4 节路径 A 直接派生。真正的 SLIP-39 份额则按路径 B 恢复。

### validate 显示 Overall Score: 0/100，但 Status: Pass

已观察到这种报告不一致的现象，原因尚未确认。检查 Format、Language、Checksum 和最终状态，不要仅凭综合评分判断；如基础检查失败或状态不明确，应停止操作并核对工具版本。即使所有格式及校验和检查通过，也不能证明它就是历史根秘密，仍须以历史密钥校验值或认证解密验证恢复。

### 派生结果与历史密钥不一致

检查原始备份、BIP-39 Passphrase、Scheme、路径、索引、长度及 sseed 版本。不得通过修改既有生产派生参数或重新生成助记词来修复恢复错误。

参考标准：[BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)、[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)、[SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)。
