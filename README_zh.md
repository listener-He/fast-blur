# FastBlur

一款高性能、轻量级的 Java 数据混淆库。FastBlur 提供了一系列类似加密的算法，能够快速、可逆地转换数据，而无需传统加密方法的开销。

## 功能特点

- **多种策略**：五种针对不同使用场景优化的实现策略
- **自适应处理**：根据数据大小自动选择最优策略
- **并行处理**：内置支持多核系统的并行执行
- **零拷贝操作**：直接缓冲区操作，最小化内存分配
- **极度轻量**：内存占用极小，无外部依赖
- **跨策略兼容**：所有策略产生一致的结果

## 使用场景

- **开发与测试**：快速混淆测试数据，无需重型加密
- **缓存系统**：保护缓存数据的轻量级转换
- **日志数据保护**：混淆日志中的敏感信息
- **数据分片**：通过可逆转换在系统间分布数据
- **性能关键应用**：传统加密太慢的场景

## 不推荐使用场景

- **安全关键应用**：这只是数据混淆，不是加密 - 不适用于保护高度敏感的数据
- **合规要求**：不满足合规性加密标准
- **长期数据存储**：不建议用于需要长期保护的数据

## 快速开始

### Maven 依赖

```xml
<dependency>
    <groupId>cn.hehouhui</groupId>
    <artifactId>fast-blur</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

### 基础用法

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

### 高级用法

```java
// 使用自定义设置创建并行处理实例
FastBlurBase encryptor = FastBlurBase.builder()
    .withEncoding(StandardCharsets.UTF_8)
    .withStrategy(FastBlurStrategy.ADAPTIVE)
    .withDynamicShift(true)
    .buildParallel();  // 启用并行处理

// 直接处理字节数组
byte[] data = "重要数据".getBytes(StandardCharsets.UTF_8);
byte[] encryptedData = encryptor.encrypt(data);
byte[] decryptedData = encryptor.decrypt(encryptedData);
```

## 架构与设计思想

FastBlur 围绕策略模式构建，允许为特定用例选择最优实现：

### 核心组件

1. **FastBlurBase**：定义接口的抽象基类
2. **策略模式**：五种专门的实现：
   - `FastBlurSimple`：最小开销实现
   - `FastBlurOptimized`：性能和内存使用的平衡
   - `FastBlurVectorized`：批处理优化
   - `FastBlurUltra`：使用查找表的最大性能

### 设计原则

- **性能优先**：算法针对速度而非安全性进行了优化
- **资源意识**：最小化内存分配和 CPU 使用
- **一致性保证**：所有策略产生相同的结果
- **并行就绪**：内置并发处理支持
- **易于集成**：简单 API，便于快速采用

## 支持特性

| 特性 | 可用性 | 说明 |
|------|--------|------|
| 固定位移模式 | ✅ | 传统位移操作 |
| 动态位移模式 | ✅ | 基于位置的位移，更好的混淆效果 |
| 并行处理 | ✅ | 自动多核利用 |
| 零拷贝操作 | ✅ | 直接缓冲区操作 |
| 自适应策略选择 | ✅ | 根据数据大小自动优化 |
| 跨策略兼容性 | ✅ | 所有策略结果一致 |

## 性能测试结果

在各种大小的测试数据上进行的性能基准测试：

### 小数据 (100 字节)
```
简单策略 (串行)     : 12 ms (10000 次迭代)
简单策略 (并行)     : 3 ms (10000 次迭代)
优化策略 (串行)     : 12 ms (10000 次迭代)
极速策略 (串行)     : 11 ms (10000 次迭代)
向量策略 (串行)     : 19 ms (10000 次迭代)
```

### 中等数据 (1,000 字节)
```
简单策略 (串行)     : 13 ms (1000 次迭代)
优化策略 (串行)     : 15 ms (1000 次迭代)
极速策略 (串行)     : 9 ms (1000 次迭代)
向量策略 (串行)     : 3 ms (1000 次迭代)
```

### 大数据 (10,000 字节)
```
简单策略 (串行)     : 15 ms (100 次迭代)
简单策略 (并行)     : 1 ms (100 次迭代)
优化策略 (串行)     : 2 ms (100 次迭代)
极速策略 (串行)     : 2 ms (100 次迭代)
向量策略 (串行)     : 2 ms (100 次迭代)
```

## 测试报告

### 一致性验证
```
加密结果一致性: 通过
解密结果一致性: 通过
原始数据恢复: 通过
所有策略结果一致，测试通过！
```

### 兼容性测试
```
跨策略兼容性: 通过
并行/串行兼容性: 通过
```

## 许可证

本项目采用 Apache-2.0 许可证 - 详情请见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎贡献！请随时提交 Pull Request。
