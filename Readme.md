# Ga1axy v2.0

[![Author](https://img.shields.io/badge/Author-ol4three-blueviolet.svg)](https://github.com/ol4three) [![Version](https://img.shields.io/badge/Version-2.0-green.svg)](https://github.com/ol4three)

> 多功能加解密工具箱 — CLI + Web 双模式，集编码/解码、哈希计算、对称加密、JWT、图片转码、Payload 生成于一体

---

## ✨ 新特性 (v2.0)

### 🌐 Web 图形界面
基于 Flask 构建的现代化 Web UI，支持深色/浅色主题切换，告别命令行参数记忆。

### 🎯 功能增强
- **一键 ALL** — 同时对全部 20+ 种加密方式批量操作，支持 DES/AES 完整参数配置
- **填入输入框** — 每个选项卡输出结果可一键回填至输入框，编解码流转丝滑
- **响应式设计** — 桌面端侧边栏导航 + 移动端自适配
- **键盘快捷键** — `Ctrl+Enter` 快速触发操作

### 📚 Hash 样本库管理
Web 界面下直接查询本地 Hash 样本库、新增样本、查看统计，离线环境依然可用。

### 🖼️ Base64 图片互转
支持图片 → Base64 编码、Base64 文本 → 图片解码，编码结果一键复制。

---

## 支持的加解密方式

| 分类 | 功能 | 支持 |
|------|------|:----:|
| **编码/解码** | URL | ✅ |
| | Unicode | ✅ |
| | Hex (3 种格式) | ✅ |
| | Base16 / Base32 / Base64 / Base85 | ✅ |
| | HTML 实体 | ✅ |
| | 摩斯密码 | ✅ |
| | 时间戳互转 | ✅ |
| **哈希** | MD5 | ✅ |
| | SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 | ✅ |
| **对称加密** | DES (ECB/CBC/CFB/OFB/EAX) | ✅ |
| | AES (ECB/CBC/CFB/OFB/EAX) | ✅ |
| **Token** | JWT 编码/解码 | ✅ |
| **图片** | Base64 图片互转 | ✅ |
| **Payload** | Runtime Payload 生成 (Bash/PowerShell/Python/Perl) | ✅ |
| **批量** | 文件逐行批量加解密 | ✅ |

---

## 快速开始

### 环境要求
- Python 3.8+
- pip

### 安装依赖

```bash
pip3 install -r requirements.txt
```

### 启动 Web 界面

```bash
# 方式一：直接启动
python3 app.py

# 方式二：使用启动脚本
bash run.sh
```

访问 `http://127.0.0.1:5002` 即可使用。

### CLI 模式（向后兼容）

v2.0 完全保留 CLI 功能，使用方式与 v1.0 一致：

```bash
python3 Ga1axy.py -base64 hello
python3 Ga1axy.py -md5 123456 -M e
python3 Ga1axy.py -aes aaa -key 1234 -iv 1234 -M e
```

详细 CLI 参数见下方 [CLI 参数](#-cli-参数) 章节。

---

## Web 界面截图

| 深色主题 | 浅色主题 |
|---------|---------|
| (默认) | 点击侧边栏 🌓 切换 |

---

## 📁 项目结构

```
.
├── app.py                 # Flask Web 后端
├── Ga1axy.py              # CLI 核心引擎 (v1.0 兼容)
├── HashDB.py              # Hash 样本库管理
├── requirements.txt       # Python 依赖
├── run.sh                 # 一键启动脚本
│
├── templates/
│   └── index.html         # Web 前端页面
│
├── static/
│   ├── css/
│   │   └── style.css      # 主题样式 (深色/浅色)
│   └── js/
│       └── app.js         # 前端交互逻辑
│
├── config/                # Hash 样本库文件 (md5/sha1/sha256/...)
├── base/
│   └── dic.txt            # 字典文件
├── result/                # 结果输出目录
├── uploads/               # 文件上传临时目录
│
├── aaa.png / bbb.png      # 测试图片
└── test.txt               # 测试文件
```

---

## 🧩 HashDB 样本库管理

### Web 界面
- 在「Hash 样本库」选项卡查看各类型样本数量
- 输入 Hash 值查询明文
- 输入明文自动计算并保存到本地样本库

### CLI 方式

```bash
python3 HashDB.py
```

通过编辑 `config/{hash_type}.txt` 文件自定义样本数据。

---

## ⚙️ CLI 参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-A` | 全部加密方式 | `python3 Ga1axy.py -A hello` |
| `-M` | 模式: `e` 编码/`d` 解码 | `-M e` / `-M d` |
| `-key` | 密钥 (DES/AES/JWT) | `-key 1234` |
| `-iv` | 偏移量 (DES/AES) | `-iv 1234` |
| `-mode` | 加密模式 (ECB/CBC/CFB/OFB/EAX) | `-mode cbc` |
| `-resu` | 结果格式 (hex/base64) | `-resu hex` |
| `-f` | 批量文件处理 | `-f test.txt` |
| `-c` | 批量处理模式选择 | `-c base64` |
| `-o` | 输出文件路径 | `-o result.txt` |

### 使用示例

```bash
# URL 编码
python3 Ga1axy.py -url https://www.baidu.com

# MD5 加密
python3 Ga1axy.py -md5 123456 -M e

# MD5 解密（需本地样本库支持）
python3 Ga1axy.py -md5 e10adc3949ba59abbe56e057f20f883e -M d

# AES-CBC 加密
python3 Ga1axy.py -aes hello -key 1234 -iv 1234 -M e -mode cbc

# DES 解密 (Hex 格式)
python3 Ga1axy.py -des 90dcbdabca2b1862 -key 1234 -M d -resu hex

# JWT 编码
python3 Ga1axy.py -jwt "{'sub':'1234567890','name':'John Doe','iat':1516239022}" -key 1234

# Base64 图片编码
python3 Ga1axy.py -baseimg aaa.png -M e

# 批量文件处理
python3 Ga1axy.py -f test.txt -c base64 -o base64.txt
```

---

## 🛠️ 技术栈

- **后端**: Python 3, Flask
- **前端**: HTML5, CSS3, JavaScript (原生)
- **加密库**: PyCryptodome, PyJWT, hashlib
- **图片处理**: Pillow

---

## 📜 许可证

本项目仅供学习研究使用。

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=OL4THREE/Ga1axy&type=Date)](https://star-history.com/#OL4THREE/Ga1axy&Date)

---

**Author: [ol4three](https://github.com/ol4three)**
