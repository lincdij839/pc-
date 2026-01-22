# PC语言 - 示例程序

本目录包含PC语言的核心示例程序，展示各类CTF功能。

## 📁 示例文件说明

### 基础示例
- **hello.pc** - Hello World入门示例

### CTF综合示例
- **ctf_all_categories.pc** - CTF 7大类别功能展示（Crypto/Pwn/Web/Reverse/Forensics/Misc/Attack-Defense）
- **ctf_verification_fast.pc** - CTF功能快速验证测试（29项测试）

### 各类别专项示例

#### Crypto（密码学）
- **rsa_demo.pc** - RSA攻击演示（Fermat分解、Wiener攻击）

#### Pwn（二进制利用）
- **exploit_gen.pc** - Exploit Payload生成器
- **rop_builder.pc** - ROP Chain构建器

#### Reverse（逆向工程）
- **reverse_demo.pc** - 逆向工程完整演示（ELF解析、ROP搜索、汇编/反汇编）
- **reverse_simple.pc** - 逆向工程简化演示（不依赖外部工具）

#### Attack-Defense（攻防）
- **attack_defense_demo.pc** - 攻防工具包演示（端口扫描、漏洞检测、防御工具）

#### OSINT（开源情报）
- **osint_demo.pc** - OSINT情报收集演示（DNS查询、GeoIP、用户名搜索、SSL证书）

## 🚀 运行示例

```bash
# 基础示例
./zig-out/bin/pc examples/hello.pc

# CTF综合测试
./zig-out/bin/pc examples/ctf_verification_fast.pc

# 逆向工程演示
./zig-out/bin/pc examples/reverse_simple.pc

# OSINT情报收集
./zig-out/bin/pc examples/osint_demo.pc

# 攻防演示
./zig-out/bin/pc examples/attack_defense_demo.pc
```

## 📊 功能覆盖

| CTF类别 | 示例文件 | 功能数 |
|---------|---------|--------|
| Crypto | rsa_demo.pc | 10+ |
| Pwn | exploit_gen.pc, rop_builder.pc | 8+ |
| Reverse | reverse_simple.pc | 14+ |
| Web | ctf_all_categories.pc | 4+ |
| Forensics | ctf_all_categories.pc | 2+ |
| Misc | ctf_all_categories.pc | 5+ |
| Attack-Defense | attack_defense_demo.pc | 13+ |
| OSINT | osint_demo.pc | 13+ |

**总计**: 10个核心示例，覆盖8大CTF类别，展示97+个CTF专用函数

## 🔧 依赖工具

某些功能需要系统安装以下工具：

### 必需工具
- `dig` - DNS查询（OSINT）
- `curl` - HTTP请求（Web/OSINT）

### 可选工具
- `python3` + `pwntools` - 汇编/反汇编、cyclic pattern
- `ROPgadget` - ROP gadget搜索
- `openssl` - SSL证书分析
- `whois` - 域名查询
- `exiftool` - 元数据提取

## 📝 注意事项

1. **运行目录**: 所有脚本需在`zig_impl`根目录下运行
2. **外部工具**: 部分高级功能需要安装外部工具（见上方列表）
3. **网络功能**: OSINT和部分Web功能需要网络连接
4. **真实性**: 所有功能均为真实实现，无模拟数据

## 🎯 推荐学习路径

1. **入门**: `hello.pc` → 基础语法
2. **CTF综合**: `ctf_verification_fast.pc` → 了解所有功能
3. **专项深入**: 
   - Pwn → `rop_builder.pc`
   - Reverse → `reverse_simple.pc`
   - OSINT → `osint_demo.pc`
   - 攻防 → `attack_defense_demo.pc`

---

**更多信息**: 查看 [../README.md](../README.md)
