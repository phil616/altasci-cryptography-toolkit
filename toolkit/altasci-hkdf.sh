#!/usr/bin/env bash
# AltasCI HKDF 密钥派生工具（Linux，OpenSSL 3）
# 单文件启动器：在专用 tmpfs 内临时编译 OpenSSL EVP_KDF 辅助程序。
# 主密钥仅在辅助进程中从终端读取，绝不出现在 argv、环境变量或普通磁盘文件。
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C
unset HISTFILE
ulimit -c 0

fail() { printf '错误：%s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || fail '必须由 root 执行（例如 sudo ./altasci-hkdf.sh）。'
for cmd in openssl cc mount umount mktemp findmnt swapon; do
    command -v "$cmd" >/dev/null 2>&1 || fail "缺少依赖：$cmd"
done
version=$(openssl version 2>/dev/null) || fail 'OpenSSL 无法执行。'
[[ $version =~ ^OpenSSL[[:space:]]3\. ]] || fail "只支持 OpenSSL 3.x，检测到：$version"
# 拒绝活动交换空间；tmpfs 页仍可能被内核换出到 swap。
swap_devices=$(swapon --noheadings --show=NAME 2>/dev/null) || fail '无法检查 swap 状态，已拒绝继续。'
[[ -z $swap_devices ]] || fail '检测到活动 swap。为避免 tmpfs 秘密页被换出，请先关闭 swap。（sudo swapon -a 或 sudo swapoff -a）'
[[ -t 0 && -t 1 ]] || fail '仅允许交互终端执行，不接受管道/重定向输入输出。'
[[ -r /usr/include/openssl/kdf.h && -r /usr/include/openssl/core_names.h ]] || fail '缺少 OpenSSL 开发头文件，请安装 libssl-dev（Debian/Ubuntu）或 openssl-devel。'
# 使用私有临时目录做挂载点；挂载成功后才把源码和二进制写进去。
mountpoint_dir=$(mktemp -d /run/altasci-hkdf.XXXXXXXX) || fail '无法在 /run 创建挂载点。'
mounted=0
cleanup() {
    local rc=$?
    trap - EXIT INT TERM HUP
    if (( mounted )); then
        # 进程退出后，卸载 tmpfs 即销毁其中的源文件、二进制和临时文件。
        umount -- "$mountpoint_dir" || printf '警告：卸载 tmpfs 失败，请手动检查：%s\n' "$mountpoint_dir" >&2
    fi
    rmdir -- "$mountpoint_dir" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mount -t tmpfs -o 'size=24m,mode=0700,nosuid,nodev' tmpfs "$mountpoint_dir" || fail '创建独立 tmpfs 失败，已拒绝继续。'
mounted=1
[[ $(findmnt -n -o FSTYPE --target "$mountpoint_dir") == tmpfs ]] || fail '内存文件系统验证失败。'
export TMPDIR="$mountpoint_dir"
cat > "$mountpoint_dir/hkdf.c" <<'C_SOURCE'
#define _GNU_SOURCE
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 所有密钥、派生材料和输入缓冲区位于锁页且禁止 core dump 的内存中。 */
typedef struct {
    char input[4096];
    unsigned char master[32];
    unsigned char output[64];
    unsigned char salt[256];
    unsigned char info[512];
    char domain[256];
} Secrets;
static int ttyfd = -1;
static struct termios original;
static int term_changed = 0;
static Secrets *sec = NULL;
static size_t memsize = 0;

static void restore(void) {
    if (term_changed && ttyfd >= 0) { tcsetattr(ttyfd, TCSAFLUSH, &original); term_changed = 0; }
}
static void cleanup(void) {
    restore();
    if (sec) { OPENSSL_cleanse(sec, sizeof(*sec)); munlock(sec, memsize); munmap(sec, memsize); sec=NULL; }
    if (ttyfd >= 0) { close(ttyfd); ttyfd = -1; }
}
static void on_signal(int sig) { restore(); _exit(128 + sig); }
static void die(const char *msg) { fprintf(stderr, "错误：%s\n", msg); exit(1); }

/* 读取一行；敏感输入不回显，长度超限直接拒绝并退出。 */
static size_t read_line(const char *prompt, char *buf, size_t cap, int hidden) {
    if (dprintf(ttyfd, "%s", prompt) < 0) die("终端不可写");
    if (hidden) {
        struct termios t = original;
        t.c_lflag &= ~(ECHO | ECHONL);
        if (tcsetattr(ttyfd, TCSAFLUSH, &t) != 0) die("无法关闭终端回显");
        term_changed = 1;
    }
    size_t n=0;
    for (;;) {
        unsigned char c;
        ssize_t r = read(ttyfd, &c, 1);
        if (r < 0 && errno == EINTR) continue;
        if (r != 1) die("终端读取失败");
        if (c == '\r' || c == '\n') break;
        if (c == 0) die("不接受 NUL 字符");
        if (n + 1 >= cap) die("输入过长");
        buf[n++] = (char)c;
    }
    buf[n] = '\0';
    if (hidden) { restore(); dprintf(ttyfd, "\n"); }
    return n;
}
static int hexdigit(char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    return -1;
}
static int parse_hex(const char *s, size_t n, unsigned char *out, size_t expected) {
    if (n != expected*2) return 0;
    for (size_t i=0;i<expected;i++) {
        int h=hexdigit(s[i*2]),l=hexdigit(s[i*2+1]);
        if (h < 0 || l < 0) return 0;
        out[i]=(unsigned char)((h<<4)|l);
    }
    return 1;
}
static int parse_colon(const char *s, size_t n, unsigned char *out) {
    if (n != 95) return 0; /* 32*2 + 31 个冒号 */
    for(size_t i=0;i<32;i++) {
        if (i<31 && s[i*3+2]!=':') return 0;
        int h=hexdigit(s[i*3]), l=hexdigit(s[i*3+1]);
        if(h<0 || l<0) return 0;
        out[i]=(unsigned char)((h<<4)|l);
    }
    return 1;
}
static int parse_b64(const char *s, size_t n, unsigned char *out) {
    /* 32 原始字节的标准 Base64 必须为 44 字符，恰好一个 '='。 */
    if(n!=44 || s[43]!='=' || s[42]=='=') return 0;
    for(size_t i=0;i<43;i++) {
        unsigned char c=(unsigned char)s[i];
        if(!(isalnum(c) || c=='+' || c=='/')) return 0;
    }
    unsigned char tmp[36]={0};
    int result=EVP_DecodeBlock(tmp,(const unsigned char*)s,(int)n);
    if(result != 33) { OPENSSL_cleanse(tmp,sizeof(tmp)); return 0; }
    /* 避免接受非规范的填充位：重新编码并按字节比较。 */
    unsigned char back[48]={0};
    int encoded=EVP_EncodeBlock(back,tmp,32);
    int good=(encoded==44 && CRYPTO_memcmp(back,s,44)==0);
    if(good) memcpy(out,tmp,32);
    OPENSSL_cleanse(tmp,sizeof(tmp)); OPENSSL_cleanse(back,sizeof(back));
    return good;
}
static int parse_pybytes(const char *s, size_t n, unsigned char *out) {
    if (n<3 || s[0]!='b' || (s[1]!='\'' && s[1]!='"') || s[n-1]!=s[1]) return 0;
    size_t w=0;
    for(size_t i=2;i<n-1;) {
        unsigned char c=(unsigned char)s[i++];
        if(c=='\\') {
            if(i>=n-1) return 0;
            char esc=s[i++];
            if(esc=='x') {
                if(i+1>=n-1) return 0;
                int h=hexdigit(s[i++]),l=hexdigit(s[i++]);
                if(h<0 || l<0) return 0;
                c=(unsigned char)((h<<4)|l);
            } else if(esc=='\\' || esc=='\'' || esc=='"') c=(unsigned char)esc;
            else if(esc=='n') c='\n';
            else if(esc=='r') c='\r';
            else if(esc=='t') c='\t';
            else return 0; /* 不支持八进制或 Unicode 转义，避免语义歧义 */
        } else if(c>127) return 0; /* 字面量只接受 ASCII，非 ASCII 请用 \\xNN */
        if(w>=32) return 0;
        out[w++]=c;
    }
    return w==32;
}
static int parse_master(const char *s, size_t n, unsigned char *out) {
    if(n==64 && parse_hex(s,n,out,32)) return 1;
    if(n==66 && s[0]=='0' && (s[1]=='x'||s[1]=='X') && parse_hex(s+2,64,out,32)) return 1;
    if(parse_colon(s,n,out)) return 1;
    if(parse_b64(s,n,out)) return 1;
    if(parse_pybytes(s,n,out)) return 1;
    return 0;
}
static void dump_hex(const unsigned char *p,size_t n,int colon) {
    for(size_t i=0;i<n;i++) { if(colon && i) putchar(':'); printf("%02x",p[i]); }
    putchar('\n');
}
static int derive(const unsigned char *master, size_t mlen, const unsigned char *salt, size_t slen,
                  const unsigned char *info,size_t ilen,unsigned char *out,size_t olen) {
    int ok=0;
    EVP_KDF *kdf=EVP_KDF_fetch(NULL,"HKDF",NULL);
    if(!kdf) return 0;
    EVP_KDF_CTX *ctx=EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if(!ctx) return 0;
    char digest[]="SHA256";
    OSSL_PARAM params[]={
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,digest,0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,(void*)master,mlen),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,(void*)salt,slen),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,(void*)info,ilen),
        OSSL_PARAM_construct_end()
    };
    ok=(EVP_KDF_derive(ctx,out,olen,params)==1);
    EVP_KDF_CTX_free(ctx);
    return ok;
}
static int selftest(void) {
    /* RFC 5869 test case 1 (SHA-256)，独立测试 EVP_KDF 正确性。 */
    unsigned char ikm[22],salt[13],info[10],out[42],expected[42];
    memset(ikm,0x0b,sizeof(ikm));
    for(size_t i=0;i<sizeof(salt);i++) salt[i]=(unsigned char)i;
    for(size_t i=0;i<sizeof(info);i++) info[i]=(unsigned char)(0xf0+i);
    if(!parse_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",84,expected,42)) return 0;
    int ok=derive(ikm,sizeof(ikm),salt,sizeof(salt),info,sizeof(info),out,sizeof(out)) && CRYPTO_memcmp(out,expected,42)==0;
    OPENSSL_cleanse(ikm,sizeof(ikm)); OPENSSL_cleanse(out,sizeof(out)); OPENSSL_cleanse(expected,sizeof(expected));
    return ok;
}
int main(int argc,char **argv) {
    if(geteuid()!=0) die("必须以 root 运行");
    if(OPENSSL_version_major()!=3) die("libcrypto 必须是 OpenSSL 3.x");
    if(prctl(PR_SET_DUMPABLE,0,0,0,0)!=0) die("无法禁止进程转储/ptrace");
    memsize=(sizeof(Secrets)+4095U)&~4095U;
    sec=mmap(NULL,memsize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(sec==MAP_FAILED) { sec=NULL; die("无法分配密钥内存"); }
    if(madvise(sec,memsize,MADV_DONTDUMP)!=0) die("无法禁止敏感内存进入 core dump");
    if(mlock(sec,memsize)!=0) die("无法锁定敏感内存（检查 RLIMIT_MEMLOCK）");
    atexit(cleanup);
    if(argc==2 && strcmp(argv[1],"--self-test")==0) {
        if(!selftest()) die("RFC 5869 自检失败");
        puts("HKDF-SHA256 自检通过（RFC 5869）。"); return 0;
    }
    if(argc!=1) die("不支持命令行传递密钥/选项；请使用交互界面");
    ttyfd=open("/dev/tty",O_RDWR|O_NOCTTY|O_CLOEXEC);
    if(ttyfd<0 || !isatty(ttyfd) || tcgetattr(ttyfd,&original)!=0) die("必须使用真实交互终端");
    struct sigaction sa={0}; sa.sa_handler=on_signal; sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL); sigaction(SIGTERM,&sa,NULL); sigaction(SIGHUP,&sa,NULL);
    puts("\n=== AltasCI HKDF 安全密钥派生工具 ===");
    puts("算法：HKDF-Extract-and-Expand / HMAC-SHA256");
    puts("主密钥：严格 32 字节（256 位）；不回显、不写入文件、不进入进程参数");
    puts("同一主密钥 + 域 + Salt + 输出长度，会产生同一结果。\n");
    size_t n=read_line("请输入主密钥（hex/base64/冒号hex/Python b'...'）：",sec->input,sizeof(sec->input),1);
    if(!parse_master(sec->input,n,sec->master)) die("主密钥格式错误，解码后必须精确为 32 字节");
    OPENSSL_cleanse(sec->input,sizeof(sec->input));
    n=read_line("请输入派生域（如 storage/db-prod，1~128 字节）：",sec->domain,sizeof(sec->domain),0);
    if(n<1 || n>128) die("派生域长度必须为 1~128 字节");
    for(size_t i=0;i<n;i++) if((unsigned char)sec->domain[i]<0x20 || (unsigned char)sec->domain[i]==0x7f) die("派生域不允许控制字符");
    const char prefix[]="AltasCI/HKDF/v1/domain/";
    memcpy(sec->info,prefix,sizeof(prefix)-1);
    memcpy(sec->info+sizeof(prefix)-1,sec->domain,n);
    size_t ilen=(sizeof(prefix)-1)+n;
    n=read_line("Salt（留空使用固定协议 Salt；或输入 hex:... / text:...）：",sec->input,sizeof(sec->input),0);
    size_t slen=0;
    const char defaultsalt[]="AltasCI/HKDF-SHA256/default-salt/v1";
    if(n==0) { slen=sizeof(defaultsalt)-1; memcpy(sec->salt,defaultsalt,slen); }
    else if(n>=4 && strncmp(sec->input,"hex:",4)==0) {
        size_t hexlen=n-4;
        if(hexlen<2 || hexlen>512 || (hexlen%2)!=0 || !parse_hex(sec->input+4,hexlen,sec->salt,hexlen/2)) die("Salt hex 格式错误，需 1~256 字节");
        slen=hexlen/2;
    } else if(n>=5 && strncmp(sec->input,"text:",5)==0) {
        slen=n-5;
        if(!slen || slen>256) die("Salt 文本长度必须为 1~256 字节");
        memcpy(sec->salt,sec->input+5,slen);
    } else die("Salt 必须留空，或使用 hex: / text: 前缀");
    OPENSSL_cleanse(sec->input,sizeof(sec->input));
    read_line("输出密钥长度（16/24/32 字节，默认 32）：",sec->input,sizeof(sec->input),0);
    size_t olen=32;
    if(sec->input[0]) {
        if(!strcmp(sec->input,"16")) olen=16;
        else if(!strcmp(sec->input,"24")) olen=24;
        else if(!strcmp(sec->input,"32")) olen=32;
        else die("AES 密钥长度仅允许 16、24、32 字节");
    }
    read_line("输出格式（hex/base64/colon，默认 hex）：",sec->input,sizeof(sec->input),0);
    int format=0;
    if(sec->input[0]) {
        if(!strcmp(sec->input,"hex")) format=0;
        else if(!strcmp(sec->input,"base64")) format=1;
        else if(!strcmp(sec->input,"colon")) format=2;
        else die("输出格式只支持 hex/base64/colon");
    }
    OPENSSL_cleanse(sec->input,sizeof(sec->input));
    if(!derive(sec->master,32,sec->salt,slen,sec->info,ilen,sec->output,olen)) die("OpenSSL HKDF 派生失败");
    /* 不在调试日志、文件或环境变量中保存派生结果。 */
    printf("\n派生成功：AES-%zu / %s\n",olen*8,format==0?"hex":format==1?"base64":"colon");
    printf("派生域：%s\n",sec->domain);
    puts("派生密钥（请妥善保存，终端输出可能被录屏或终端日志记录）：");
    if(format==0) dump_hex(sec->output,olen,0);
    else if(format==2) dump_hex(sec->output,olen,1);
    else { unsigned char b64[128]={0}; EVP_EncodeBlock(b64,sec->output,(int)olen); puts((char*)b64); OPENSSL_cleanse(b64,sizeof(b64)); }
    return 0;
}
C_SOURCE
# 使用严格的链接和编译选项，构建文件、编译器临时文件都在 tmpfs。
cc -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    "$mountpoint_dir/hkdf.c" -o "$mountpoint_dir/hkdf" -lcrypto || fail '编译失败，请检查 GCC/Clang 与 OpenSSL 3 开发库。'
"$mountpoint_dir/hkdf" --self-test || fail 'OpenSSL HKDF 自检失败。'
"$mountpoint_dir/hkdf" "$@"
