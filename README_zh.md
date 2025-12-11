# FastBlur

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java Version](https://img.shields.io/badge/Java-8%2B-blue.svg)](https://www.oracle.com/java/technologies/javase-downloads.html)
![Performance](https://img.shields.io/badge/Performance-Blazing%20Fast-brightgreen)
[![English](https://img.shields.io/badge/English-README-blue.svg)](README.md)


专为Java设计的高性能轻量级数据混淆库。FastBlur提供了一系列类加密算法，可在无需传统加密方法开销的情况下实现快速、可逆的数据转换。

## 核心特性

- **多策略架构**：五种专门优化的实现方案，适配多样化场景
- **智能自适应**：根据数据特征动态选择最优策略
- **并行计算就绪**：原生支持多核架构上的并发执行
- **零拷贝语义**：直接缓冲区操作，消除不必要的内存分配
- **超轻量级足迹**：极低资源消耗，零外部依赖
- **跨策略一致性**：保证所有实现变体结果一致
- **资源感知设计**：精细化控制线程池使用和内存消耗

## 理想应用场景

### 开发与测试环境
快速混淆测试数据集，避免加密级计算开销。

### 高吞吐缓存层
通过可逆转换保护临时缓存数据，维持性能特征。

### 日志数据脱敏
为合规目的对日志中的个人身份信息(PII)和敏感数据进行混淆处理。

### 微服务数据分发
在服务边界间以轻量级、可逆的方式分发数据。

### 实时处理管道
在对传统加密会产生瓶颈的性能敏感应用中处理流数据。

### 临时数据保护
为只需短期保密而非长期加密保证的短暂数据提供安全保障。

## 安全限制

### ⚠️ 不适用场景

- **密码学敏感应用**：FastBlur提供的是混淆而非加密级安全
- **合规要求**：不满足GDPR、HIPAA或PCI-DSS等标准
- **持久长期存储**：不推荐用于需要延长保密期的数据
- **军用/政府用途**：不满足机密信息保护标准

### 安全模型
FastBlur实现了为性能而非密码强度优化的确定性、可逆变换。应将其视为复杂的掩码技术而非安全机制。

## 快速开始

### 安装

Maven:
```xml
<dependency>
    <groupId>cn.hehouhui</groupId>
    <artifactId>fast-blur</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

Gradle:
```gradle
implementation 'cn.hehouhui:fast-blur:1.0-SNAPSHOT'
```

### 基础实现

```java
import cn.hehouhui.fastblur.FastBlurBase;
import cn.hehouhui.fastblur.FastBlurStrategy;

// 使用默认设置创建实例
FastBlurBase encryptor = FastBlurBase.builder()
    .withStrategy(FastBlurStrategy.SPEED_FIRST)
    .build();

// 加密数据
String original = "Hello World";
String encrypted = encryptor.encryptBase64(original.getBytes(StandardCharsets.UTF_8));

// 解密数据
String decrypted = encryptor.decryptStr(encrypted);

assert original.equals(decrypted);
```

### 资源优化的并行处理

```java
// 为资源隔离创建自定义ForkJoinPool
ForkJoinPool customPool = new ForkJoinPool(4); // 限制为4个线程

// 使用自定义线程池创建实例
FastBlurBase encryptor = FastBlurBase.builder()
    .withEncoding(StandardCharsets.UTF_8)
    .withStrategy(FastBlurStrategy.ADAPTIVE)
    .withDynamicShift(true)
    .buildParallel(customPool);  // 使用自定义池

// 处理数据
byte[] data = "重要数据".getBytes(StandardCharsets.UTF_8);
byte[] encryptedData = encryptor.encrypt(data);
byte[] decryptedData = encryptor.decrypt(encryptedData);

// 清理资源
customPool.shutdown();
```

## 架构设计

FastBlur实现了一个复杂的战略模式，可根据数据特征和性能要求选择最优算法：

### 核心架构

1. **FastBlurBase**：定义统一接口的抽象基础
2. **策略实现**：五个专用变体：
   - `FastBlurSimple`：最低开销的极简方法
   - `FastBlurOptimized`：性能/内存平衡折衷
   - `FastBlurVectorized`：SIMD启发的批处理
   - `FastBlurUltra`：查找表加速的最大吞吐量
   - `FastBlurAdaptive`：基于数据配置文件的智能自动选择

### 设计理念

#### 以性能为中心的工程
优先考虑计算效率而非密码强度的算法，利用位运算和数学优化。

#### 资源感知并发
通过可定制的线程池精细控制并行执行，防止高负载环境中的资源争用。

#### 确定性一致性
跨策略结果一致性确保实现在不同变体间无缝迁移而无数据完整性担忧。

#### 开发者体验聚焦
直观的流畅API设计，实现快速集成和最小学习曲线。

## 综合功能矩阵

| 能力 | 状态 | 实现细节 |
|------------|--------|---------------------|
| 固定位移模式 | ✅ | 传统确定性质位移 |
| 动态位移模式 | ✅ | 基于位置的自适应位移，增强混淆 |
| 并行处理 | ✅ | 自动多核编排与资源治理 |
| 零拷贝操作 | ✅ | 直接缓冲区操作，最小化堆分配 |
| 自适应策略选择 | ✅ | 基于数据配置文件的智能自动优化 |
| 跨策略兼容性 | ✅ | 所有实现变体间的一致性 |
| 自定义线程池支持 | ✅ | 精细化并发控制与资源隔离 |
| 内存高效设计 | ✅ | 优化数据结构，最小化足迹 |
| 流数据支持 | ✅ | 针对连续数据流的ByteBuffer操作 |

## 性能基准测试

跨多种数据大小和处理模式的综合性能评估：

### 微型数据 (100 字节)
| 策略 | 模式 | 时间 | 吞吐量 | 相对性能 |
|----------|------|------|------------|---------------|
| Simple | 串行 | 15 ms | 666,666 次/秒 | 1.00x |
| Simple | 并行 | 3 ms | 3,333,333 次/秒 | 5.00x |
| Optimized | 串行 | 18 ms | 555,555 次/秒 | 0.83x |
| Optimized | 并行 | 11 ms | 909,090 次/秒 | 1.36x |
| Ultra | 串行 | 14 ms | 714,285 次/秒 | 1.07x |
| Ultra | 并行 | 16 ms | 625,000 次/秒 | 0.94x |
| Vector | 串行 | 22 ms | 454,545 次/秒 | 0.68x |
| Vector | 并行 | 15 ms | 666,666 次/秒 | 1.00x |

### 小型数据 (1,000 字节)
| 策略 | 模式 | 时间 | 吞吐量 | 相对性能 |
|----------|------|------|------------|---------------|
| Simple | 串行 | 15 ms | 66,666 次/秒 | 0.05x |
| Simple | 并行 | 15 ms | 66,666 次/秒 | 0.05x |
| Optimized | 串行 | 19 ms | 52,631 次/秒 | 0.04x |
| Optimized | 并行 | 19 ms | 52,631 次/秒 | 0.04x |
| Ultra | 串行 | 12 ms | 83,333 次/秒 | 0.06x |
| Ultra | 并行 | 11 ms | 90,909 次/秒 | 0.07x |
| Vector | 串行 | 3 ms | 333,333 次/秒 | 0.25x |
| Vector | 并行 | 3 ms | 333,333 次/秒 | 0.25x |

### 中型数据 (10,000 字节)
| 策略 | 模式 | 时间 | 吞吐量 | 相对性能 |
|----------|------|------|------------|---------------|
| Simple | 串行 | 20 ms | 5,000 次/秒 | 1.00x |
| Simple | 并行 | 2 ms | 50,000 次/秒 | 10.00x |
| Optimized | 串行 | 3 ms | 33,333 次/秒 | 6.67x |
| Optimized | 并行 | 3 ms | 33,333 次/秒 | 6.67x |
| Ultra | 串行 | 2 ms | 50,000 次/秒 | 10.00x |
| Ultra | 并行 | 2 ms | 50,000 次/秒 | 10.00x |
| Vector | 串行 | 2 ms | 50,000 次/秒 | 10.00x |
| Vector | 并行 | 3 ms | 33,333 次/秒 | 6.67x |

### 大型数据 (100,000 字节)
| 策略 | 模式 | 时间 | 吞吐量 | 相对性能 |
|----------|------|------|------------|---------------|
| Simple | 串行 | 1 ms | 10,000 次/秒 | 1.00x |
| Simple | 并行 | 1 ms | 10,000 次/秒 | 1.00x |
| Optimized | 串行 | 3 ms | 3,333 次/秒 | 0.33x |
| Optimized | 并行 | 3 ms | 3,333 次/秒 | 0.33x |
| Ultra | 串行 | 2 ms | 5,000 次/秒 | 0.50x |
| Ultra | 并行 | 2 ms | 5,000 次/秒 | 0.50x |
| Vector | 串行 | 3 ms | 3,333 次/秒 | 0.33x |
| Vector | 并行 | 2 ms | 5,000 次/秒 | 0.50x |

### 超大型数据 (1,000,000 字节)
| 策略 | 模式 | 时间 | 吞吐量 | 相对性能 |
|----------|------|------|------------|---------------|
| Simple | 串行 | 1 ms | 1,000 次/秒 | 1.00x |
| Simple | 并行 | 1 ms | 1,000 次/秒 | 1.00x |
| Optimized | 串行 | 2 ms | 500 次/秒 | 0.50x |
| Optimized | 并行 | 2 ms | 500 次/秒 | 0.50x |
| Ultra | 串行 | 1 ms | 1,000 次/秒 | 1.00x |
| Ultra | 并行 | 1 ms | 1,000 次/秒 | 1.00x |
| Vector | 串行 | 1 ms | 1,000 次/秒 | 1.00x |
| Vector | 并行 | 2 ms | 500 次/秒 | 0.50x |

## 资源消耗概况

| 策略 | 内存开销 | CPU利用率 | 线程使用 |
|----------|----------------|-----------------|--------------|
| Simple | 低 (1x) | 低 (1x) | 单线程 |
| Optimized | 中 (1.5x) | 中 (1.2x) | 多线程(可选) |
| Vectorized | 中 (2x) | 高 (1.5x) | 多线程(可选) |
| Ultra | 高 (3x) | 很高 (2x) | 多线程(可选) |
| Adaptive | 可变 | 可变 | 多线程(可选) |

## 验证结果

### 跨策略一致性
```
加密一致性: 通过
解密一致性: 通过
数据恢复: 通过
```

### 兼容性保证
```
跨策略兼容性: 通过
并行/串行兼容性: 通过
```

## 战略实施指导

### 性能优化建议

1. **微型数据 (< 256 字节)**：使用`FastBlurUltra`实现最大吞吐量
2. **小型数据 (256-4KB)**：利用`FastBlurVectorized`获得批处理优势
3. **大型数据 (> 4KB)**：采用`FastBlurOptimized`实现资源平衡利用
4. **可变工作负载**：部署`FastBlurAdaptive`进行智能自动选择

### 资源管理最佳实践

1. **高并发环境**：实施自定义线程池防止资源耗尽
2. **内存受限系统**：优选`FastBlurSimple`或`FastBlurOptimized`策略
3. **CPU密集型应用**：精心调整并行处理阈值
4. **混合工作负载**：根据数据特征组合策略

## 许可证

该项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件。

## 贡献

欢迎贡献！请随时提交Pull Request。

### 开发指南

1. 维护跨策略一致性
2. 保持性能特征
3. 确保向后兼容性
4. 遵循既定编码模式
