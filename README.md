# FastBlur

High-performance, lightweight data obfuscation library for Java. FastBlur provides a suite of encryption-like algorithms that offer fast, reversible data transformation without the overhead of traditional cryptographic methods.

## Features

- **Multiple Strategies**: Five different implementation strategies optimized for various use cases
- **Adaptive Processing**: Automatically selects optimal strategy based on data size
- **Parallel Processing**: Built-in support for parallel execution on multi-core systems
- **Zero-copy Operations**: Direct buffer manipulation to minimize memory allocations
- **Extremely Lightweight**: Minimal memory footprint and no external dependencies
- **Cross-strategy Compatibility**: All strategies produce consistent results

## Use Cases

- **Development & Testing**: Quickly obfuscate test data without heavy encryption
- **Caching Systems**: Protect cached data with lightweight transformation
- **Log Data Protection**: Obfuscate sensitive information in logs
- **Data Sharding**: Distribute data across systems with reversible transformation
- **Performance-Critical Applications**: Where traditional encryption is too slow

## Not Recommended For

- **Security-Critical Applications**: This is obfuscation, not encryption - not suitable for protecting highly sensitive data
- **Regulatory Compliance**: Does not meet cryptographic standards for compliance requirements
- **Long-term Data Storage**: Not recommended for data that needs long-term protection

## Quick Start

### Maven Dependency

```xml
<dependency>
    <groupId>cn.hehouhui</groupId>
    <artifactId>fast-blur</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

### Basic Usage

```java
import cn.hehouhui.fastblur.FastBlurBase;
import cn.hehouhui.fastblur.FastBlurStrategy;

// Create an instance with default settings
FastBlurBase encryptor = FastBlurBase.builder()
    .withStrategy(FastBlurStrategy.SPEED_FIRST)
    .build();

// Encrypt data
String original = "Hello World";
String encrypted = encryptor.encryptBase64(original.getBytes(StandardCharsets.UTF_8));

// Decrypt data
String decrypted = encryptor.decryptStr(encrypted);

assert original.equals(decrypted);
```

### Advanced Usage

```java
// Create a parallel-processing instance with custom settings
FastBlurBase encryptor = FastBlurBase.builder()
    .withEncoding(StandardCharsets.UTF_8)
    .withStrategy(FastBlurStrategy.ADAPTIVE)
    .withDynamicShift(true)
    .buildParallel();  // Enable parallel processing

// Work directly with byte arrays
byte[] data = "Important data".getBytes(StandardCharsets.UTF_8);
byte[] encryptedData = encryptor.encrypt(data);
byte[] decryptedData = encryptor.decrypt(encryptedData);
```

## Architecture & Design Philosophy

FastBlur is built around a strategy pattern that allows selecting the optimal implementation for specific use cases:

### Core Components

1. **FastBlurBase**: Abstract base class defining the interface
2. **Strategy Pattern**: Five specialized implementations:
   - `FastBlurSimple`: Minimal overhead implementation
   - `FastBlurOptimized`: Balanced performance and memory usage
   - `FastBlurVectorized`: Batch processing optimizations
   - `FastBlurUltra`: Maximum performance with lookup tables

### Design Principles

- **Performance First**: Algorithms optimized for speed over security
- **Resource Conscious**: Minimize memory allocations and CPU usage
- **Consistency Guaranteed**: All strategies produce identical results
- **Parallel Ready**: Built-in support for concurrent processing
- **Easy Integration**: Simple API for quick adoption

## Supported Features

| Feature | Available | Notes |
|---------|-----------|-------|
| Fixed Shift Mode | ✅ | Traditional bit shifting |
| Dynamic Shift Mode | ✅ | Position-based shifting for better obfuscation |
| Parallel Processing | ✅ | Automatic multi-core utilization |
| Zero-copy Operations | ✅ | Direct buffer manipulation |
| Adaptive Strategy Selection | ✅ | Auto-optimization by data size |
| Cross-strategy Compatibility | ✅ | Consistent results across all strategies |

## Performance Test Results

Performance benchmarks conducted on test data of various sizes:

### Small Data (100 bytes)
```
Simple Strategy (Serial)    : 12 ms (10000 iterations)
Simple Strategy (Parallel)  : 3 ms (10000 iterations)
Optimized Strategy (Serial) : 12 ms (10000 iterations)
Ultra Strategy (Serial)     : 11 ms (10000 iterations)
Vector Strategy (Serial)    : 19 ms (10000 iterations)
```

### Medium Data (1,000 bytes)
```
Simple Strategy (Serial)    : 13 ms (1000 iterations)
Optimized Strategy (Serial) : 15 ms (1000 iterations)
Ultra Strategy (Serial)     : 9 ms (1000 iterations)
Vector Strategy (Serial)    : 3 ms (1000 iterations)
```

### Large Data (10,000 bytes)
```
Simple Strategy (Serial)    : 15 ms (100 iterations)
Simple Strategy (Parallel)  : 1 ms (100 iterations)
Optimized Strategy (Serial) : 2 ms (100 iterations)
Ultra Strategy (Serial)     : 2 ms (100 iterations)
Vector Strategy (Serial)    : 2 ms (100 iterations)
```

## Test Reports

### Consistency Verification
```
Encryption Result Consistency: PASSED
Decryption Result Consistency: PASSED
Original Data Recovery: PASSED
All strategies produce consistent results - TEST PASSED!
```

### Compatibility Testing
```
Cross-strategy Compatibility: PASSED
Parallel/Serial Compatibility: PASSED
```

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
