# ELF 文件分析工具--测试版本

一个使用 Rust 编写的 ELF 文件分析工具，支持本地静态分析和在线沙箱/威胁情报查询。

## 功能特性

- **ELF 文件解析**: 分析 ELF 文件的基本信息、程序头、节头、符号表等
- **哈希计算**: 计算文件的 MD5、SHA1、SHA256 哈希值
- **字符串提取**: 从二进制文件中提取可读字符串
- **在线威胁情报**: 支持 VirusTotal 和 Hybrid Analysis API 查询
- **多种输出格式**: 支持文本和 JSON 格式输出
- **配置灵活**: 支持配置文件和环境变量配置

## 安装要求

- Rust 1.70 或更高版本
- 网络连接（用于在线分析）

## 编译安装

```bash
# 克隆项目（如果从 git 仓库）
git clone <repository-url>
cd elf-analyzer

# 编译项目
cargo build --release

# 安装到系统（可选）
cargo install --path .
```

## 配置

### 1. 配置文件方式

复制示例配置文件并编辑：

```bash
cp config.example.json config.json
```

编辑 `config.json` 文件，填入你的 API 密钥：

```json
{
  "virustotal_api_key": "你的VirusTotal API密钥",
  "hybrid_analysis_api_key": "你的Hybrid Analysis API密钥",
  "malware_bazaar_api_key": "你的Malware Bazaar API密钥",
  "timeout_seconds": 30,
  "max_retries": 3
}
```

### 2. 环境变量方式

```bash
export VIRUSTOTAL_API_KEY="你的VirusTotal API密钥"
export HYBRID_ANALYSIS_API_KEY="你的Hybrid Analysis API密钥"
export MALWARE_BAZAAR_API_KEY="你的Malware Bazaar API密钥"
```

## API 密钥获取

- **VirusTotal**: 访问 [VirusTotal](https://www.virustotal.com/gui/join-us) 注册账户获取免费 API 密钥
- **Hybrid Analysis**: 访问 [Hybrid Analysis](https://www.hybrid-analysis.com/signup) 注册账户获取 API 密钥

## 使用方法

### 基本用法

```bash
# 分析单个 ELF 文件
./target/release/elf-analyzer /path/to/elf/file

# 使用配置文件
./target/release/elf-analyzer -c config.json /path/to/elf/file

# 启用在线分析
./target/release/elf-analyzer --online /path/to/elf/file

# 输出 JSON 格式
./target/release/elf-analyzer --output json /path/to/elf/file

# 仅显示基本信息（不进行在线查询）
./target/release/elf-analyzer --basic-only /path/to/elf/file
```

### 命令行参数

```
Usage: elf-analyzer [OPTIONS] <FILE>

Arguments:
  <FILE>  要分析的ELF文件路径

Options:
  -c, --config <CONFIG>      配置文件路径
  -o, --output <OUTPUT>      输出格式 (text/json) [default: text]
      --online               启用在线分析
      --basic-only           仅显示基本ELF信息
  -h, --help                 Print help
```

## 输出示例

### 文本格式输出

```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                         ELF 文件分析报告                                                 ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝

📁 基本信息:
   文件路径: /bin/ls
   文件大小: 138208 bytes
   架构: x86_64
   入口点: 0x6040

🔐 文件哈希:
   MD5:    5d41402abc4b2a76b9719d911017c592
   SHA1:   aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
   SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

🌐 在线分析结果:
   🔍 VirusTotal:
      检测结果: 0/70 引擎检测到威胁
      详细报告: https://www.virustotal.com/gui/file/...
```

### JSON 格式输出

```json
{
  "elf_info": {
    "file_path": "/bin/ls",
    "file_size": 138208,
    "architecture": "x86_64",
    "entry_point": 24640,
    "hashes": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  },
  "online_analysis": {
    "virustotal": {
      "positives": 0,
      "total": 70,
      "permalink": "https://www.virustotal.com/gui/file/..."
    }
  }
}
```

## 安全说明

⚠️ **重要安全提醒**:

1. **仅用于防御性安全分析**: 本工具设计用于恶意软件分析、威胁检测和防御性安全研究
2. **API 密钥保护**: 请妥善保管你的 API 密钥，不要将其提交到版本控制系统
3. **样本隔离**: 分析恶意样本时请在隔离环境中运行
4. **合规使用**: 请确保你有权限分析目标文件，遵守相关法律法规

## 技术架构

- **ELF 解析**: 使用 `goblin` crate 进行 ELF 文件解析
- **哈希计算**: 使用 `sha2`、`sha1`、`md5` crate 计算文件哈希
- **HTTP 客户端**: 使用 `reqwest` 进行 API 调用
- **命令行解析**: 使用 `clap` 处理命令行参数
- **配置管理**: 支持 JSON 配置文件和环境变量

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个工具。

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 免责声明

本工具仅供合法的安全研究和防御目的使用。使用者需要自行承担使用本工具的风险和责任。开发者不对因使用本工具而导致的任何损失或法律问题承担责任。
