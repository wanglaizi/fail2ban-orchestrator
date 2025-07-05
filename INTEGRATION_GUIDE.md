# 系统集成指南

本指南说明如何集成和部署分布式Fail2ban系统的各个组件，包括基础功能和增强功能的统一部署方案。

> **相关文档**: 
> - 基础安装: [README.md](README.md)
> - 详细配置: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
> - 增强功能: [enhancements/README.md](enhancements/README.md)

## 集成架构

系统采用模块化架构，支持灵活的部署模式：

```
┌─────────────────────────────────────────────────────────────┐
│                    统一启动入口 (main.py)                    │
├─────────────────────────────────────────────────────────────┤
│  基础组件: 中央服务器 | 代理节点 | 执行节点 | Web界面        │
├─────────────────────────────────────────────────────────────┤
│  增强功能: 多租户 | 智能告警 | 性能监控 | ML检测 | 安全审计   │
└─────────────────────────────────────────────────────────────┘
```

## 部署模式

系统支持多种部署模式，可根据实际需求选择：

### 运行模式

| 模式 | 描述 | 适用场景 |
|------|------|----------|
| `central` | 中央控制服务器 | 分布式部署的控制节点 |
| `agent` | 日志收集代理 | 各服务器的日志收集 |
| `executor` | 封禁执行节点 | 防火墙规则执行 |
| `enhanced` | 仅增强功能 | 独立的增强功能服务 |
| `all` | 完整系统 | 单机部署（推荐） |

### 启动命令

```bash
# 单机完整部署（推荐）
python main.py --mode all --config config_enhanced.yaml

# 分布式部署
python main.py --mode central --config config.yaml    # 控制节点
python main.py --mode agent --config config.yaml      # 代理节点
python main.py --mode executor --config config.yaml   # 执行节点
python main.py --mode enhanced --config config.yaml   # 增强功能
```

## 配置集成

### 基础配置 + 增强功能

在 `config.yaml` 中添加增强功能配置：

```yaml
# 基础系统配置
system:
  debug: false
  log_level: INFO

# 增强功能配置
enhancements:
  enabled: true
  multi_tenancy:
    enabled: true
  intelligent_alerting:
    enabled: true
  # 更多配置请参考 enhancements/README.md
```

## 部署场景

### 场景1：单机部署（推荐新用户）

适用于中小型环境，所有功能运行在一台服务器上：

```bash
# 1. 生成配置文件
python main.py --init-config

# 2. 启动完整系统
python main.py --mode all --config config_enhanced.yaml

# 访问Web界面
# http://localhost:8080
```

### 场景2：分布式部署（企业级）

适用于大型环境，组件分布在不同服务器：

```bash
# 控制中心服务器 (192.168.1.10)
python main.py --mode central --config config.yaml

# 增强功能服务器 (192.168.1.11)
python main.py --mode enhanced --config config_enhanced.yaml

# Web服务器节点 (192.168.1.20-29)
python main.py --mode agent --config config.yaml

# 防火墙节点 (192.168.1.30-39)
python main.py --mode executor --config config.yaml
```

### 场景3：渐进式升级

从基础系统逐步启用增强功能：

```bash
# 1. 部署基础系统
python main.py --mode all --config config.yaml

# 2. 测试基础功能正常后，启用增强功能
# 编辑 config.yaml，添加 enhancements 配置

# 3. 重启系统
python main.py --mode all --config config.yaml
```

## 依赖管理

### 自动安装（推荐）

```bash
# 安装所有依赖
pip install -r requirements.txt

# 或使用安装脚本
./install.sh
```

### 手动安装

```bash
# 基础功能依赖
pip install pyyaml requests flask psutil redis pymongo

# 增强功能依赖（可选）
pip install scikit-learn numpy pandas cryptography
```

## 容错机制

系统设计了完善的容错机制：

- **模块缺失**: 增强功能依赖缺失时自动降级到基础功能
- **配置错误**: 提供详细错误信息和修复建议
- **服务故障**: 单个模块故障不影响其他功能
- **网络异常**: 自动重连和故障转移

## 运维监控

### 日志管理

```bash
# 查看系统日志
tail -f logs/fail2ban.log

# 查看错误日志
grep ERROR logs/fail2ban.log

# 查看特定模块日志
grep "enhancement" logs/fail2ban.log
```

### 健康检查

```bash
# 检查服务状态
curl http://localhost:8080/api/health

# 检查各模块状态
python main.py --health-check
```

## 最佳实践

### 1. 部署前准备

- **环境检查**: 确认Python版本、依赖库、网络连接
- **配置验证**: 使用 `--validate-config` 检查配置文件
- **权限设置**: 确保日志目录、数据目录有写权限
- **防火墙配置**: 开放必要的端口（8080, 6379, 27017等）

### 2. 生产环境配置

- **安全加固**: 修改默认密码，启用HTTPS，限制API访问
- **性能调优**: 根据负载调整工作进程数和缓存大小
- **监控告警**: 配置系统监控和告警通知
- **备份策略**: 定期备份配置文件和数据库

### 3. 故障排除

- **日志分析**: 优先检查错误日志和警告信息
- **网络诊断**: 验证节点间网络连接和端口可达性
- **资源监控**: 检查CPU、内存、磁盘使用情况
- **配置检查**: 确认配置文件语法和参数正确性

## 升级指南

### 版本升级

```bash
# 1. 备份当前系统
cp -r . ../fail2ban-backup-$(date +%Y%m%d)

# 2. 停止服务
pkill -f "python main.py"

# 3. 更新代码
git pull origin main

# 4. 更新依赖
pip install -r requirements.txt

# 5. 检查配置兼容性
python main.py --validate-config

# 6. 重启服务
python main.py --mode all --config config.yaml
```

### 配置迁移

从旧版本迁移配置时，请参考配置模板：

```bash
# 生成新版本配置模板
python main.py --init-config --template enhanced

# 对比并合并配置
diff config.yaml.old config.yaml
```

## 技术支持

### 问题排查顺序

1. **检查日志**: `tail -f logs/fail2ban.log`
2. **验证配置**: `python main.py --validate-config`
3. **测试网络**: `python main.py --test-connection`
4. **检查依赖**: `pip list | grep -E "(flask|redis|pymongo)"`

### 获取帮助

- **文档**: [README.md](README.md) | [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- **增强功能**: [enhancements/README.md](enhancements/README.md)
- **问题反馈**: GitHub Issues
- **社区支持**: 项目讨论区

---

**提示**: 生产环境部署前建议先在测试环境验证所有功能正常。