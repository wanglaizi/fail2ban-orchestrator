# 🛡️ 分布式Nginx日志监控与Fail2ban封禁系统

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)]()

## 📋 项目概述

本项目是一个基于多台服务器的**分布式Nginx日志监控和动态IP封禁系统**，专为三网（电信、联通、移动）和海外主机环境设计，支持CentOS和Ubuntu操作系统。系统通过实时分析Nginx访问日志，自动识别恶意攻击行为，并利用Fail2ban在多个节点间协调执行IP封禁操作。

### 🎯 核心特性

- 🌐 **分布式架构**: 支持多台服务器协同工作，适配三网和海外部署
- ⚡ **实时监控**: 基于文件监控的毫秒级日志分析
- 🧠 **智能分析**: 多种攻击模式识别（SQL注入、XSS、路径遍历、命令注入等）
- 🎯 **动态封禁**: 基于风险评分和机器学习的自动封禁决策
- 📊 **Web界面**: 现代化的管理和监控仪表板
- 🔄 **高可用性**: 支持节点故障恢复和负载均衡
- 📱 **多渠道通知**: 支持邮件、钉钉、微信、Slack等通知方式
- 🔐 **安全加固**: API密钥认证、请求限流、数据加密
- 🚀 **增强功能**: 多租户管理、智能告警、性能监控、安全审计、ML攻击检测

## 🏗️ 系统架构

系统采用分布式架构，包含以下核心组件：

- **中央控制节点**: 负责日志分析、攻击检测和封禁协调
- **增强功能层**: 提供多租户管理、智能告警、性能监控、ML检测等高级功能
- **日志收集代理**: 实时监控各服务器的Nginx日志
- **封禁执行节点**: 执行具体的IP封禁操作
- **Web管理界面**: 提供可视化监控和管理功能

### 架构图

![系统架构图](docs/architecture.svg)

系统支持三网环境（电信、联通、移动）和海外环境的分布式部署，通过中央控制节点协调各个代理和执行节点，实现智能化的攻击检测和封禁管理。

> 📖 详细的系统架构图和组件说明请参考 [用户手册](docs/USER_GUIDE.md#系统架构)

## 🛠️ 技术栈

- **编程语言**: Python 3.7+
- **Web框架**: FastAPI + Uvicorn
- **数据存储**: Redis + MongoDB
- **封禁工具**: Fail2ban
- **Web服务器**: Nginx
- **操作系统**: CentOS 7/8, Ubuntu 18.04+

> 📖 详细的技术要求和版本信息请参考 [用户手册](docs/USER_GUIDE.md#系统要求)

## 🚀 快速开始

### 📋 系统要求

- **操作系统**: Linux (CentOS 7/8 或 Ubuntu 18.04+)
- **Python版本**: 3.7+
- **权限要求**: Root权限
- **内存要求**: 至少2GB RAM

### 📦 一键安装

```bash
# 下载并运行安装脚本
wget https://github.com/wanglaizi/fail2ban-orchestrator/archive/main.zip
unzip main.zip && cd fail2ban-distributed-main
chmod +x install.sh && sudo ./install.sh
```

安装脚本支持以下模式：
- **[1] 中央控制节点** - 主控服务器
- **[2] 日志收集代理** - 监控服务器
- **[3] 封禁执行节点** - 执行服务器
- **[4] 完整系统** - 单机部署（推荐）

### ⚙️ 手动安装

```bash
# 安装依赖
pip3 install -r requirements.txt

# 生成配置文件
python3 main.py --init-config

# 启动系统
python3 main.py --mode all
```

> 📖 详细的手动安装步骤请参考 [用户手册](docs/USER_GUIDE.md#安装部署)

### 🔧 配置说明

系统支持多种运行模式和配置选项：

```yaml
# 基础配置示例
system:
  mode: "all"  # central, agent, executor, enhanced, all
  log_level: "INFO"

# 增强功能配置
enhancements:
  enabled: true  # 启用增强功能
  multi_tenancy:
    enabled: true
  intelligent_alerting:
    enabled: true
```

> 📖 完整的配置说明请参考 [集成指南](INTEGRATION_GUIDE.md) 和 [用户手册](docs/USER_GUIDE.md#配置说明)

### 🌐 访问Web界面

安装完成后，访问Web管理界面：

- **URL**: `http://your-server-ip:8080`
- **默认账户**: admin / admin123 (可在配置中修改)

## 📖 文档导航

- 📚 **[用户手册](docs/USER_GUIDE.md)** - 详细的使用指南和配置说明
- 🔌 **[API文档](docs/API.md)** - RESTful API接口文档
- 🚀 **[集成指南](INTEGRATION_GUIDE.md)** - 增强功能集成和使用
- ⚡ **[快速开始](enhancements/QUICKSTART.md)** - 增强功能快速启动指南

## 🎯 运行模式

系统支持多种运行模式，满足不同的部署需求：

| 模式 | 描述 | 适用场景 |
|------|------|----------|
| `central` | 中央控制服务器 | 主控节点部署 |
| `agent` | 日志收集代理 | 监控节点部署 |
| `executor` | 封禁执行节点 | 执行节点部署 |
| `enhanced` | 增强功能模块 | 高级功能部署 |
| `all` | 完整系统 | 单机部署（推荐） |

```bash
# 启动不同模式
python3 main.py --mode central    # 中央控制
python3 main.py --mode enhanced   # 增强功能
python3 main.py --mode all        # 完整系统
```

## 📁 项目结构

```
fail2ban-distributed/
├── 📄 main.py                 # 主程序入口
├── ⚙️ config.example.yaml     # 配置文件模板
├── 📋 requirements.txt        # Python依赖清单
├── 🚀 install.sh             # 一键安装脚本
├── 🏢 central/               # 中央控制节点
├── 🤖 agents/                # 日志收集代理
├── 🛠️ utils/                 # 工具模块
├── 🔍 analysis/              # 智能分析模块
├── 📢 notifications/         # 通知推送模块
├── 🌐 web/                   # Web管理界面
├── 🚀 enhancements/          # 增强功能模块
└── 📖 docs/                  # 文档目录
```

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出建议！

- 🐛 **报告问题**: 在GitHub上创建Issue
- 💡 **功能建议**: 在GitHub Discussions中讨论
- 🔧 **代码贡献**: Fork项目并提交Pull Request

> 📖 详细的贡献指南请参考 [用户手册](docs/USER_GUIDE.md#贡献指南)

## 📄 许可证

本项目采用MIT许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Fail2ban](https://www.fail2ban.org/) - 强大的入侵防护工具
- [FastAPI](https://fastapi.tiangolo.com/) - 现代化的Python Web框架
- [Redis](https://redis.io/) - 高性能内存数据库
- [MongoDB](https://www.mongodb.com/) - 灵活的文档数据库
- [Nginx](https://nginx.org/) - 高性能Web服务器

---

<div align="center">
  <p>如果这个项目对你有帮助，请给它一个 ⭐ Star！</p>
  <p>Made with ❤️ by the Fail2ban Distributed Team</p>
</div>

## 许可证

MIT License