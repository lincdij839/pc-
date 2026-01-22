# PC語言 (PC Language)

一門融合 **Python 語法** 與 **C/C++ 性能** 的現代編程語言，專為黑客和系統編程設計。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Language: Zig](https://img.shields.io/badge/Language-Zig-orange.svg)](https://ziglang.org/)
[![Completion: 95%](https://img.shields.io/badge/Completion-95%25-brightgreen.svg)]()

## 🌟 核心特性

- **🐍 Python 風格語法** - 縮進式語法、無分號、直觀易讀
- **⚡ C/C++ 級性能** - 接近原生性能，支持手動內存管理
- **🔗 FFI 支持** - 直接調用 C/C++ 函數
- **🛠️ 內建黑客工具** - PWN 模組（pack/unpack、process 等）
- **🔐 密碼學工具鏈** - Hash、RSA攻擊、編碼等 CTF 必備功能
- **📦 單文件編譯** - 編譯成獨立可執行文件
- **⚙️ HolyC 風格執行** - 直接運行，無需子命令

## 📦 安裝

### 前置需求
- Zig 0.13.0+

### 構建
```bash
git clone https://github.com/your-username/pc-language.git
cd pc-language/zig_impl
zig build
```

## 🚀 快速開始

### Hello World
```python
# hello.pc
print("Hello, PC Language!")
```

運行：
```bash
./zig-out/bin/pc hello.pc
```

### 變數和運算
```python
x = 100
y = 20
result = x + y
print(result)  # 120
```

### 函數定義
```python
def add(a, b):
    return a + b

result = add(10, 20)
print(result)  # 30
```

### 控制流
```python
x = 10
if x > 5:
    print("大於 5")
else:
    print("小於等於 5")

# while 循環
i = 0
while i < 5:
    print(i)
    i = i + 1

# for 循環
for i in range(10):
    print(i)
```

### 列表和字典
```python
# 列表操作
nums = [1, 2, 3]
nums[0] = 999
print(nums[0])  # 999
nums = append(nums, 4)
print(len(nums))  # 4

# 字典操作
config = {"host": "localhost", "port": 8080}
config["host"] = "192.168.1.1"
print(config["host"])  # 192.168.1.1
print(keys(config))  # ["host", "port"]
```

### PWN 模組
```python
# 十六進制字面量
addr = 0x401234
print(hex(addr))  # 0x401234

# Pack/Unpack
packed = p64(addr)
unpacked = unpack64(packed)
print(hex(unpacked))  # 0x401234
```

### 密碼學模組
```python
# Hash 函數
data = "password123"
print(md5(data))     # MD5 雜湊
print(sha256(data))  # SHA256 雜湊

# Base64 編碼
encoded = base64_encode("secret")
decoded = base64_decode(encoded)
print(decoded)  # "secret"

# XOR 加密
plaintext = "flag"
key = "key"
encrypted = xor_bytes(plaintext, key)
decrypted = xor_bytes(encrypted, key)
print(decrypted)  # "flag"

# RSA 小數分解
n = 143  # 13 * 11
result = rsa_factor_small(n)
print(result)  # {"p": 11, "q": 13, "factored": true}

# AES 加密（需要 pycryptodome）
plaintext = "sensitive_data"
key = "0123456789abcdef"  # 16 bytes
iv = "fedcba9876543210"   # 16 bytes
encrypted = aes_encrypt(plaintext, key, iv)
decrypted = aes_decrypt(encrypted, key, iv)
print(decrypted)  # "sensitive_data"

# 文件操作
data = read_file("/tmp/flag.txt")
write_file("/tmp/output.txt", data)

# 大整數轉換（CTF 常用）
bytes_data = "flag"
n = bytes_to_long(bytes_data)
recovered = long_to_bytes(n)
print(recovered)  # "flag"
```

## 📚 標準庫

### 基礎函數
- `print(x)` - 輸出到標準輸出
- `len(x)` - 返回長度（支持字串、列表、字典）
- `range(n)` - 生成範圍

### OSINT（開源情報）模組
- `geoip(ip)` - IP 地理位置查詢（國家、城市、ISP）
- `reverse_dns(ip)` - 反向 DNS 查詢
- `dns_lookup(domain, record_type)` - DNS 記錄查詢
- `whois(domain)` - WHOIS 域名查詢
- `subdomain_enum(domain)` - 子域名枚舉
- `email_verify(email)` - 郵箱驗證（MX 記錄檢查）
- `username_search(username)` - 用戶名跨平台搜索
- `google_dork(keyword, site, filetype)` - Google Dork 生成器
- `wayback_check(url)` - Wayback Machine 檢查
- `http_headers(url)` - HTTP 頭信息提取
- `ssl_cert_info(domain)` - SSL 證書信息查詢
- `extract_metadata(file_path)` - 文件元數據提取
- `shodan_search(query, api_key)` - Shodan API 搜索

### Attack-Defense（攻防）模組
- `scan_port(host, port)` - 單端口掃描
- `scan_ports(host, ports)` - 多端口掃描
- `scan_common_ports(host)` - 常見端口掃描
- `get_banner(host, port)` - 服務 Banner 獲取
- `detect_service(host, port)` - 服務檢測
- `check_vuln_sql(url)` - SQL 注入檢測
- `check_vuln_xss(url)` - XSS 漏洞檢測
- `ping(host)` - Ping 主機
- `traceroute(host)` - 路由追踪
- `craft_tcp_syn(dst_ip, dst_port)` - 構造 TCP SYN 包
- `detect_port_scan(log_file)` - 端口掃描檢測
- `block_ip(ip)` - 生成 IP 封禁命令
- `check_rate_limit(ip, threshold)` - 檢查訪問頻率

### 類型轉換
- `str(x)` - 轉換為字串
- `int(x)` - 轉換為整數

### 數學函數
- `abs(x)` - 絕對值
- `max(a, b)` - 最大值
- `min(a, b)` - 最小值
- `pow(base, exp)` - 冪運算

### 字串函數
- `upper(s)` - 轉大寫
- `lower(s)` - 轉小寫

### 列表函數
- `append(list, item)` - 添加元素（返回新列表）

### 字典函數
- `keys(dict)` - 返回鍵列表
- `values(dict)` - 返回值列表

### PWN 模組
- `p32(value)` - 打包 32 位整數（小端）
- `p64(value)` - 打包 64 位整數（小端）
- `unpack32(bytes)` - 解包 32 位整數
- `unpack64(bytes)` - 解包 64 位整數
- `hex(value)` - 轉換為十六進制字串

### 密碼學模組

#### Hash 函數
- `md5(data)` - MD5 雜湊
- `sha1(data)` - SHA1 雜湊
- `sha256(data)` - SHA256 雜湊
- `sha512(data)` - SHA512 雜湊

#### 編碼函數
- `base64_encode(data)` - Base64 編碼
- `base64_decode(data)` - Base64 解碼
- `hex_encode(data)` - 十六進制編碼
- `hex_decode(hex_string)` - 十六進制解碼

#### 加密函數
- `xor_bytes(data, key)` - XOR 加密/解密
- `rot13(text)` - ROT13 密碼

#### RSA 攻擊函數
- `rsa_parse_pem(pem_string)` - 解析 PEM 格式公鑰
- `rsa_factor_small(n)` - 小數試除法分解
- `rsa_attack_fermat(n_hex)` - Fermat 分解攻擊
- `rsa_attack_wiener(n_hex, e_hex)` - Wiener 攻擊（小私鑰）
- `rsa_attack_factordb(n_hex)` - FactorDB 查詢分解
- `rsa_compute_d(p, q, e)` - 計算私鑰 d
- `rsa_decrypt_with_pqe(c, p, q, e)` - RSA 解密
- `rsa_common_e()` - 返回常見 RSA 指數列表

#### AES 加密（需要 pycryptodome）
- `aes_encrypt(plaintext, key, iv)` - AES-128-CBC 加密
- `aes_decrypt(ciphertext, key, iv)` - AES-128-CBC 解密

#### 文件操作
- `read_file(path)` - 讀取文件（二進制）
- `write_file(path, data)` - 寫入文件（二進制）

#### CTF 工具函數
- `bytes_to_long(bytes)` - 字節轉大整數（大端序）
- `long_to_bytes(n)` - 大整數轉字節（大端序）
- `shellcode_execve(cmd)` - 生成 shellcode（需要 pwntools）

### 數字字面量
- `0x...` - 十六進制（例：0x401234）
- `0o...` - 八進制（例：0o755）
- `0b...` - 二進制（例：0b1010）

## 📊 項目狀態

| 模組 | 完成度 | 狀態 |
|------|--------|------|
| Lexer | 100% | ✅ 完成 |
| Parser | 98% | ✅ 完成 |
| 解釋器 | 98% | ✅ 完成 |
| 標準庫 | 95% | ✅ 完成 |
| PWN 模組 | 90% | ✅ 完成 |
| 密碼學模組 | 98% | ✅ 完成 |
| Reverse 模組 | 85% | ✅ 完成 |
| OSINT 模組 | 65% | 🚧 開發中 |
| Attack-Defense | 75% | 🚧 開發中 |
| Web 安全 | 80% | ✅ 完成 |
| Forensics | 70% | 🚧 開發中 |
| 文件操作 | 100% | ✅ 完成 |
| 數據結構 | 95% | ✅ 列表/字典完成 |
| LLVM 後端 | 0% | 📋 計劃中 |

**總體完成度：85.7%**（CTF 實戰可用）

## 🛠️ 技術架構

- **實現語言**：Zig 0.13.0
- **解釋器類型**：Tree-walking interpreter
- **內存管理**：GPA (General Purpose Allocator)
- **數據結構**：ArrayList, HashMap

## 📝 範例程序

查看 [examples/](examples/) 目錄獲取更多範例（已精簡至 10 個核心示例）：

### 基礎示例
- `hello.pc` - Hello World 入門示例

### CTF 綜合測試
- `ctf_all_categories.pc` - CTF 7 大類別功能展示
- `ctf_verification_fast.pc` - CTF 功能快速驗證（29 項測試）

### Crypto（密碼學）
- `rsa_demo.pc` - RSA 攻擊演示（Fermat 分解、Wiener 攻擊）

### Pwn（二進制利用）
- `exploit_gen.pc` - Exploit Payload 生成器
- `rop_builder.pc` - ROP Chain 構建器

### Reverse（逆向工程）
- `reverse_demo.pc` - 逆向工程完整演示（ELF 解析、ROP 搜索）
- `reverse_simple.pc` - 逆向工程簡化演示（不依賴外部工具）

### Attack-Defense（攻防）
- `attack_defense_demo.pc` - 攻防工具包演示（端口掃描、漏洞檢測）

### OSINT（開源情報）
- `osint_demo.pc` - OSINT 情報收集演示（DNS、GeoIP、用戶名搜索）
- `ip_tracker.pc` - IP 地址位置追蹤工具（實時地理位置查詢）

**功能覆蓋**：10 個核心示例，覆蓋 8 大 CTF 類別，展示 97+ 個 CTF 專用函數

詳細說明請查看 [examples/README.md](examples/README.md)

## 🧪 測試

運行測試套件：
```bash
./complete_test.sh
```

運行演示腳本：
```bash
./demo.sh
```

## 📖 文檔

- [進度報告](PROGRESS.md) - 詳細的開發進度和功能清單
- [語法設計](../docs/) - 語言設計文檔

## 🤝 貢獻

歡迎貢獻！請查看待實現功能：

### 高優先級
- [ ] 完善縮進處理（INDENT/DEDENT token）
- [ ] 字串 split/join/replace 函數
- [ ] process 類（PWN 模組）

### 中優先級
- [ ] class 定義和對象系統
- [ ] 模組系統（import）
- [ ] 列表切片語法（list[1:3]）

### 低優先級
- [ ] LLVM 後端（編譯成機器碼）
- [ ] 異常處理（try/except）
- [ ] 類型標注系統

### ✅ 已完成
- [x] 列表數據結構和操作
- [x] 字典數據結構和操作
- [x] 字典/列表索引賦值（dict[key] = value）
- [x] 十六進制/八進制/二進制字面量
- [x] 字符串拼接和字符串乘法（"=" * 60）
- [x] 密碼學工具鏈（Hash、RSA、編碼）
- [x] AES 加密/解密（CBC 模式）
- [x] 文件讀寫操作（二進制）
- [x] CTF 常用工具函數（bytes_to_long 等）
- [x] OSINT 開源情報模組（13 個函數）
- [x] Attack-Defense 攻防模組（13 個函數）
- [x] 逆向工程模組（ELF 解析、ROP 搜索）
- [x] IP 地址位置追蹤工具

## 📄 許可證

MIT License - 詳見 [LICENSE](LICENSE) 文件

## 👤 作者

PC語言由 [@yuan](https://github.com/your-username) 開發

## 🙏 致謝

- [Zig](https://ziglang.org/) - 優秀的系統編程語言
- Python 社區 - 語法設計靈感
- pwntools - PWN 模組設計參考

## 📮 聯繫

- Issues: [GitHub Issues](https://github.com/your-username/pc-language/issues)
- Discussions: [GitHub Discussions](https://github.com/your-username/pc-language/discussions)

---

**注意**：PC語言目前處於早期開發階段，API 可能會發生變化。
