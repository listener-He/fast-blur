package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

/**
 * Simple lightweight obfuscation algorithm (ultra version).
 * <br/>
 * High-performance reversible lightweight encryption tool (supports fixed shift and
 * dynamic shift enhanced obfuscation, security not guaranteed). Core: dynamic shift +
 * XOR bitwise operations, extremely fast, reversible, obfuscation superior to fixed shift.
 *
 * <p>This class provides a simple data obfuscation mechanism that implements
 * reversible data transformation through dynamic shift and XOR operations.
 * Compared to ordinary versions, extreme performance optimizations have been made,
 * suitable for lightweight data protection scenarios requiring extreme performance.</p>
 *
 * <p>Extreme optimizations:
 * 1. Use lookup tables to completely avoid bitwise operations
 * 2. Unroll small loops to reduce branch prediction failures
 * 3. Pre-compute all possible shift results
 * 4. Avoid all unnecessary object creation
 * 5. Utilize CPU cache-friendly access patterns
 * 6. Support both fixed shift and dynamic shift modes
 * </p>
 *
 * <p>Design Philosophy:
 * The ultra version represents the pinnacle of performance optimization for the
 * FastBlur algorithm. It trades memory for speed by pre-computing lookup tables,
 * making it ideal for scenarios where maximum throughput is required regardless
 * of memory constraints.
 * </p>
 *
 * <p>Usage example:
 * <pre>{@code
 * FastBlurUltra encryptor = new FastBlurUltra();
 * String original = "Hello World";
 * String encrypted = encryptor.encryptBase64(original.getBytes(StandardCharsets.UTF_8));
 * String decrypted = encryptor.decryptStr(encrypted);
 * assert original.equals(decrypted);
 * }</pre>
 * </p>
 *
 * @author HeHui
 * @since 1.0
 * @see FastBlurBase
 * @see FastBlurStrategy#SPEED_FIRST
 */
public class FastBlurUltra extends FastBlurBase {

    /**
     * Left circular shift lookup table.
     * <br/>
     * Pre-computed lookup table for left circular shifts. Indexed by shift amount
     * (0-7) and byte value (0-255). This table eliminates the need for runtime
     * bitwise operations, trading memory for speed.
     *
     * <p>Structure:
     * - First dimension: shift amount (0-7)
     * - Second dimension: byte value (0-255)
     * - Value: result of left circular shift
     * </p>
     *
     * @see #rightShiftTable
     * @see FastBlurUtils#rotateLeft(int, int)
     */
    private final byte[][] leftShiftTable;

    /**
     * Right circular shift lookup table.
     * <br/>
     * Pre-computed lookup table for right circular shifts. Indexed by shift amount
     * (0-7) and byte value (0-255). This table eliminates the need for runtime
     * bitwise operations, trading memory for speed.
     *
     * <p>Structure:
     * - First dimension: shift amount (0-7)
     * - Second dimension: byte value (0-255)
     * - Value: result of right circular shift
     * </p>
     *
     * @see #leftShiftTable
     * @see FastBlurUtils#rotateRight(int, int)
     */
    private final byte[][] rightShiftTable;

    /**
     * Default constructor using UTF-8 character set encoding.
     * <br/>
     * Initializes a FastBlurUltra instance with UTF-8 encoding and default
     * configuration values. Dynamic shifting is enabled and parallel processing
     * is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra();
     * }</pre>
     * </p>
     *
     * @see StandardCharsets#UTF_8
     */
    public FastBlurUltra() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * Constructor initializing a FastBlurUltra instance with the specified encoding.
     * <br/>
     * Initializes a FastBlurUltra instance with the given character encoding and
     * default key and shift values. Dynamic shifting is enabled and parallel processing
     * is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding character encoding method
     * @see Charset
     */
    public FastBlurUltra(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF), false);
    }

    /**
     * Constructor initializing a FastBlurUltra instance with the specified encoding,
     * key, and key segment (dynamic shift mode).
     * <br/>
     * Initializes a FastBlurUltra instance in dynamic shift mode with the given
     * parameters. Parallel processing is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding    character encoding method
     * @param key         64-bit key
     * @param keySegment  key segment value for dynamic shift calculation
     * @see Charset
     */
    public FastBlurUltra(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, false);
    }

    /**
     * Constructor initializing a FastBlurUltra instance with the specified encoding,
     * key, key segment, and parallel processing option (dynamic shift mode).
     * <br/>
     * Initializes a FastBlurUltra instance in dynamic shift mode with the given
     * parameters. Parallel processing can be enabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
     * }</pre>
     * </p>
     *
     * @param encoding           character encoding method
     * @param key                64-bit key
     * @param keySegment         key segment value for dynamic shift calculation
     * @param parallelProcessing whether to enable parallel processing
     * @see Charset
     * @see #parallelProcessing
     */
    public FastBlurUltra(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        this(encoding, key, keySegment, true, parallelProcessing, null);
    }

    /**
     * Constructor initializing a FastBlurUltra instance with the specified encoding,
     * key, shift parameter, dynamic shift option, and parallel processing option.
     * <br/>
     * Fully configurable constructor for FastBlurUltra instances.
     *
     * <p>Lookup Table Initialization:
     * In dynamic shift mode, pre-computes lookup tables for all possible shift
     * operations to eliminate runtime bitwise computations.
     * </p>
     *
     * @param encoding           character encoding method
     * @param key                64-bit key (dynamic shift) or key for XOR operations (fixed shift)
     * @param shiftParam         key segment value (dynamic shift) or fixed shift value (fixed shift, 0-7)
     * @param dynamicShift       whether to enable dynamic shift
     * @param parallelProcessing whether to enable parallel processing
     * @see Charset
     * @see #dynamicShift
     * @see #parallelProcessing
     * @see #leftShiftTable
     * @see #rightShiftTable
     */
    public FastBlurUltra(Charset encoding, long key, int shiftParam, boolean dynamicShift, boolean parallelProcessing, java.util.concurrent.ForkJoinPool customPool) {
        super(encoding, parallelProcessing, dynamicShift,
              dynamicShift ? (byte) (key & 0xFF) : (byte) (key & 0xFF),
              dynamicShift ? (byte) ((key >> 8) & 0xFF) : (byte) 0,
              dynamicShift ? shiftParam & 0xFF : 0,
              dynamicShift ? 0 : shiftParam & 0x7, customPool);

        // 预计算查找表（仅在动态位移模式下需要）
        if (dynamicShift) {
            this.leftShiftTable = new byte[8][256];
            this.rightShiftTable = new byte[8][256];

            for (int shift = 0; shift < 8; shift++) {
                for (int b = 0; b < 256; b++) {
                    // 左循环位移
                    leftShiftTable[shift][b] = (byte) (FastBlurUtils.rotateLeft(b, shift) & 0xFF);
                    // 右循环位移
                    rightShiftTable[shift][b] = (byte) (FastBlurUtils.rotateRight(b, shift) & 0xFF);
                }
            }
        } else {
            this.leftShiftTable = null;
            this.rightShiftTable = null;
        }
    }

    /**
     * Constructor initializing a FastBlurUltra instance with the specified encoding,
     * key, shift parameter, dynamic shift option, and custom ForkJoinPool.
     * <br/>
     * Fully configurable constructor for FastBlurUltra instances with custom ForkJoinPool.
     *
     * @param encoding           character encoding method
     * @param key                64-bit key (dynamic shift) or key for XOR operations (fixed shift)
     * @param shiftParam         key segment value (dynamic shift) or fixed shift value (fixed shift, 0-7)
     * @param dynamicShift       whether to enable dynamic shift
     * @param pool               custom ForkJoinPool for parallel processing
     * @see Charset
     * @see #dynamicShift
     */
    public FastBlurUltra(Charset encoding, long key, int shiftParam, boolean dynamicShift, java.util.concurrent.ForkJoinPool pool) {
        super(encoding, true, dynamicShift,
              dynamicShift ? (byte) (key & 0xFF) : (byte) (key & 0xFF),
              dynamicShift ? (byte) ((key >> 8) & 0xFF) : (byte) 0,
              dynamicShift ? shiftParam & 0xFF : 0,
              dynamicShift ? 0 : shiftParam & 0x7,
              pool);

        // 预计算查找表（仅在动态位移模式下需要）
        if (dynamicShift) {
            this.leftShiftTable = new byte[8][256];
            this.rightShiftTable = new byte[8][256];

            for (int shift = 0; shift < 8; shift++) {
                for (int b = 0; b < 256; b++) {
                    // 左循环位移
                    leftShiftTable[shift][b] = (byte) (FastBlurUtils.rotateLeft(b, shift) & 0xFF);
                    // 右循环位移
                    rightShiftTable[shift][b] = (byte) (FastBlurUtils.rotateRight(b, shift) & 0xFF);
                }
            }
        } else {
            this.leftShiftTable = null;
            this.rightShiftTable = null;
        }
    }

    /**
     * Encrypts a byte array (supports fixed shift and dynamic shift enhanced obfuscation).
     * <br/>
     * The encryption process consists of three steps (dynamic shift) or two steps (fixed shift):
     * Dynamic shift mode:
     * 1. XOR the data with the first part of the key
     * 2. Perform dynamic circular left shift on the result
     * 3. XOR the result with the second part of the key
     *
     * Fixed shift mode:
     * 1. XOR the data with the key
     * 2. Perform fixed circular left shift on the result
     *
     * <p>Algorithm Details:
     * In dynamic shift mode:
     * 1. XOR data with first key fragment ({@link #keyPart1})
     * 2. Apply dynamic circular left shift using lookup table ({@link #leftShiftTable})
     * 3. XOR result with second key fragment ({@link #keyPart2})
     *
     * In fixed shift mode:
     * 1. XOR data with the key ({@link #keyPart1})
     * 2. Apply fixed circular left shift ({@link #shift})
     * </p>
     *
     * <p>Performance Optimizations:
     * - For large data (≥16KB) with {@link #parallelProcessing} enabled, uses parallel processing
     * - For small data (≤256 bytes) in dynamic mode, uses specialized small data optimization ({@link #encryptSmall(byte[])})
     * - For small data (≤128 bytes) in fixed mode, uses unrolled loop optimization ({@link #encryptUnrolled(byte[])})
     * - Operates directly on input array to avoid memory copy overhead
     * - Uses lookup tables to eliminate bitwise operations in dynamic mode
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurUltra encryptor = new FastBlurUltra();
     * byte[] original = "Hello".getBytes(StandardCharsets.UTF_8);
     * byte[] encrypted = encryptor.encrypt(original);
     * }
     * </pre>
     * </p>
     *
     * @param data the original byte array
     * @return the encrypted byte array (same array as input)
     * @throws IllegalArgumentException if the input data is malformed
     * @see #decrypt(byte[])
     * @see #dynamicShift
     * @see #parallelProcessing
     * @see #leftShiftTable
     */
    @Override
    public byte[] encrypt(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }

        // 如果启用了并行处理且数据足够大，则使用并行处理
        if (parallelProcessing && data.length >= 16384) {
            return encryptParallel(data);
        }

        if (dynamicShift) {
            // 动态位移模式
            // 对于小数据(<=256字节)，使用小数据优化方法
            if (data.length <= 256) {
                return encryptSmall(data);
            }

            // 直接在原数组上操作，避免数组复制开销
            final int len = data.length;
            for (int i = 0; i < len; i++) {
                // 将byte转换为unsigned int以用作查找表索引
                final int b = data[i] & 0xFF;

                // 步骤1：第一段密钥异或
                final int xored1 = b ^ (keyPart1 & 0xFF);

                // 获取动态位移值
                final int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);

                // 步骤2：动态循环左移（使用查找表）
                final int shifted = leftShiftTable[dynamicShift][xored1] & 0xFF;

                // 步骤3：第二段密钥异或
                data[i] = (byte) (shifted ^ (keyPart2 & 0xFF));
            }
        } else {
            // 固定位移模式
            // 对于小数据(<=128字节)，使用展开循环优化
            if (data.length <= 128) {
                return encryptUnrolled(data);
            }

            // 直接在原数组上操作，避免数组复制开销
            for (int i = 0; i < data.length; i++) {
                // 步骤1：密钥异或
                data[i] ^= keyPart1;

                // 步骤2：固定循环左移
                if (shift != 0) {
                    int unsigned = data[i] & 0xFF;
                    int shifted = FastBlurUtils.rotateLeft(unsigned, shift);
                    data[i] = (byte) (shifted & 0xFF);
                }
            }
        }
        return data;
    }

    /**
     * Unrolled loop encryption method for small data (fixed shift mode).
     * <br/>
     * Specifically optimized for data less than or equal to 128 bytes.
     *
     * <p>Optimization Techniques:
     * <ul>
     *   <li>Loop unrolling to reduce branch prediction misses</li>
     *   <li>Local variable caching of frequently accessed fields</li>
     *   <li>Processing 8 bytes at a time in the unrolled loop</li>
     *   <li>Used only in fixed shift mode</li>
     * </ul>
     * </p>
     *
     * @param data the original byte array
     * @return the encrypted byte array (same array as input)
     * @see #encrypt(byte[])
     * @see #dynamicShift
     */
    private byte[] encryptUnrolled(byte[] data) {
        final int len = data.length;
        final byte kp1 = keyPart1;
        final int sh = shift;

        // 展开循环以减少分支开销
        int i = 0;
        for (; i <= len - 8; i += 8) {
            // 处理8个字节
            data[i] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i] & 0xFF;
                data[i] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }

            data[i+1] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i+1] & 0xFF;
                data[i+1] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }

            data[i+2] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i+2] & 0xFF;
                data[i+2] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }

            data[i+3] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i+3] & 0xFF;
                data[i+3] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }

            data[i+4] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i+4] & 0xFF;
                data[i+4] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }

            data[i+5] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i+5] & 0xFF;
                data[i+5] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }

            data[i+6] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i+6] & 0xFF;
                data[i+6] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }

            data[i+7] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i+7] & 0xFF;
                data[i+7] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }
        }

        // 处理剩余字节
        for (; i < len; i++) {
            data[i] ^= kp1;
            if (sh != 0) {
                int unsigned = data[i] & 0xFF;
                data[i] = (byte) (FastBlurUtils.rotateLeft(unsigned, sh) & 0xFF);
            }
        }

        return data;
    }

    /**
     * Fast encryption method for small data (unrolled loop version).
     * <br/>
     * Specifically optimized for data less than or equal to 256 bytes.
     *
     * <p>Optimization Techniques:
     * <ul>
     *   <li>Completely unrolled loops for very small data (≤8 bytes)</li>
     *   <li>Switch-based dispatch for optimal branch prediction</li>
     *   <li>Lookup table-based shift operations to eliminate bitwise computations</li>
     *   <li>Batch processing for larger small data (64-256 bytes) in {@link #encryptSmallBatch(byte[])}</li>
     * </ul>
     * </p>
     *
     * <p>Algorithm:
     * For each byte in the data:
     * 1. XOR with first key fragment ({@link #keyPart1})
     * 2. Apply dynamic circular left shift using lookup table ({@link #leftShiftTable})
     * 3. XOR with second key fragment ({@link #keyPart2})
     * </p>
     *
     * @param data the original byte array (length must be ≤256)
     * @return the encrypted byte array (same array as input)
     * @see #encrypt(byte[])
     * @see #dynamicShift
     * @see #encryptSmallBatch(byte[])
     * @see #leftShiftTable
     */
    public byte[] encryptSmall(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }

        final int len = data.length;

        // 对于大于64字节的数据，使用批量处理
        if (len > 64) {
            return encryptSmallBatch(data);
        }

        // 展开小循环以减少分支开销
        switch (len) {
            case 8:
                data[7] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(7, shiftMask)][(data[7] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 7:
                data[6] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(6, shiftMask)][(data[6] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 6:
                data[5] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(5, shiftMask)][(data[5] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 5:
                data[4] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(4, shiftMask)][(data[4] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 4:
                data[3] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(3, shiftMask)][(data[3] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 3:
                data[2] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(2, shiftMask)][(data[2] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 2:
                data[1] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(1, shiftMask)][(data[1] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 1:
                data[0] = (byte) ((leftShiftTable[FastBlurUtils.getDynamicShift(0, shiftMask)][(data[0] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            default:
                // 不应该到达这里
                break;
        }
        return data;
    }

    /**
     * Batch processing encryption method for small data.
     * <br/>
     * Specifically optimized for 64-256 byte data.
     *
     * <p>Optimization Techniques:
     * <ul>
     *   <li>Reduced function call overhead through batching</li>
     *   <li>Local variable caching of frequently accessed fields
     *   <li>Lookup table-based shift operations to eliminate bitwise computations</li>
     * </ul>
     * </p>
     *
     * <p>Algorithm:
     * For each byte in the data:
     * 1. XOR with first key fragment ({@link #keyPart1})
     * 2. Apply dynamic circular left shift using lookup table ({@link #leftShiftTable})
     * 3. XOR with second key fragment ({@link #keyPart2})
     * </p>
     *
     * @param data the original byte array
     * @return the encrypted byte array (same array as input)
     * @see #encryptSmall(byte[])
     * @see #dynamicShift
     * @see #leftShiftTable
     */
    private byte[] encryptSmallBatch(byte[] data) {
        final int len = data.length;
        final byte kp1 = keyPart1;
        final byte kp2 = keyPart2;
        final int mask = shiftMask;

        // 批量处理以减少函数调用开销
        for (int i = 0; i < len; i++) {
            int dynamicShift = FastBlurUtils.getDynamicShift(i, mask);
            int b = data[i] & 0xFF;
            int xored1 = b ^ (kp1 & 0xFF);
            int shifted = leftShiftTable[dynamicShift][xored1] & 0xFF;
            data[i] = (byte) (shifted ^ (kp2 & 0xFF));
        }

        return data;
    }

    /**
     * 解密字节数组（加密的逆操作，动态位移还原）
     *
     * <p>解密是加密的逆向操作，其步骤顺序与加密相反：
     * 1. 使用密钥的第二部分与数据进行异或运算（逆向步骤3）
     * 2. 对结果进行动态循环右移（逆向步骤2）
     * 3. 使用密钥的第一部分与数据进行异或运算（逆向步骤1）</p>
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurUltra encryptor = new FastBlurUltra();
     * byte[] encrypted = ...; // 已加密的字节数组
     * byte[] decrypted = encryptor.decrypt(encrypted);
     * }</pre>
     * </p>
     *
     * @param encryptedData 加密后的字节数组
     * @return 原始字节数组
     */
    @Override
    public byte[] decrypt(byte[] encryptedData) {
        if (encryptedData == null || encryptedData.length == 0) {
            return encryptedData;
        }

        // 如果启用了并行处理且数据足够大，则使用并行处理
        if (parallelProcessing && encryptedData.length >= 16384) {
            return decryptParallel(encryptedData);
        }

        if (dynamicShift) {
            // 动态位移模式
            // 对于小数据(<=256字节)，使用小数据优化方法
            if (encryptedData.length <= 256) {
                return decryptSmall(encryptedData);
            }

            // 直接在原数组上操作，避免数组复制开销
            final int len = encryptedData.length;
            for (int i = 0; i < len; i++) {
                // 将byte转换为unsigned int以用作查找表索引
                final int b = encryptedData[i] & 0xFF;

                // 逆步骤3：第二段密钥异或还原
                final int xored1 = b ^ (keyPart2 & 0xFF);

                // 获取动态位移值（使用相同的规则）
                final int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);

                // 逆步骤2：动态循环右移（使用查找表）
                final int shifted = rightShiftTable[dynamicShift][xored1] & 0xFF;

                // 逆步骤1：第一段密钥异或还原
                encryptedData[i] = (byte) (shifted ^ (keyPart1 & 0xFF));
            }
        } else {
            // 固定位移模式
            // 对于小数据(<=128字节)，使用展开循环优化
            if (encryptedData.length <= 128) {
                return decryptUnrolled(encryptedData);
            }

            // 直接在原数组上操作，避免数组复制开销
            for (int i = 0; i < encryptedData.length; i++) {
                // 步骤1：密钥异或
                encryptedData[i] ^= keyPart1;

                // 步骤2：固定循环右移
                if (shift != 0) {
                    int unsigned = encryptedData[i] & 0xFF;
                    int shifted = FastBlurUtils.rotateRight(unsigned, shift);
                    encryptedData[i] = (byte) (shifted & 0xFF);
                }
            }
        }
        return encryptedData;
    }

    /**
     * 展开循环的小数据解密方法（固定位移模式）
     * 专门针对小于等于128字节的数据进行优化
     *
     * @param encryptedData 加密后的字节数组
     * @return 原始字节数组
     */
    private byte[] decryptUnrolled(byte[] encryptedData) {
        final int len = encryptedData.length;
        final byte kp1 = keyPart1;
        final int sh = shift;

        // 展开循环以减少分支开销
        int i = 0;
        for (; i <= len - 8; i += 8) {
            // 处理8个字节
            encryptedData[i] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }

            encryptedData[i+1] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i+1] & 0xFF;
                encryptedData[i+1] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }

            encryptedData[i+2] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i+2] & 0xFF;
                encryptedData[i+2] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }

            encryptedData[i+3] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i+3] & 0xFF;
                encryptedData[i+3] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }

            encryptedData[i+4] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i+4] & 0xFF;
                encryptedData[i+4] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }

            encryptedData[i+5] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i+5] & 0xFF;
                encryptedData[i+5] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }

            encryptedData[i+6] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i+6] & 0xFF;
                encryptedData[i+6] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }

            encryptedData[i+7] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i+7] & 0xFF;
                encryptedData[i+7] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }
        }

        // 处理剩余字节
        for (; i < len; i++) {
            encryptedData[i] ^= kp1;
            if (sh != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (FastBlurUtils.rotateRight(unsigned, sh) & 0xFF);
            }
        }

        return encryptedData;
    }

    /**
     * 小数据量快速解密方法（展开循环版本）
     * 专门针对小于等于256字节的数据进行优化
     *
     * @param encryptedData 加密后的字节数组（长度必须<=256）
     * @return 原始字节数组
     */
    public byte[] decryptSmall(byte[] encryptedData) {
        if (encryptedData == null || encryptedData.length == 0) {
            return encryptedData;
        }

        final int len = encryptedData.length;

        // 对于大于64字节的数据，使用批量处理
        if (len > 64) {
            return decryptSmallBatch(encryptedData);
        }

        // 展开小循环以减少分支开销
        switch (len) {
            case 8:
                encryptedData[7] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(7, shiftMask)][(encryptedData[7] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 7:
                encryptedData[6] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(6, shiftMask)][(encryptedData[6] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 6:
                encryptedData[5] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(5, shiftMask)][(encryptedData[5] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 5:
                encryptedData[4] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(4, shiftMask)][(encryptedData[4] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 4:
                encryptedData[3] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(3, shiftMask)][(encryptedData[3] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 3:
                encryptedData[2] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(2, shiftMask)][(encryptedData[2] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 2:
                encryptedData[1] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(1, shiftMask)][(encryptedData[1] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 1:
                encryptedData[0] = (byte) ((rightShiftTable[FastBlurUtils.getDynamicShift(0, shiftMask)][(encryptedData[0] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            default:
                // 不应该到达这里
                break;
        }
        return encryptedData;
    }

    /**
     * 批量处理的小数据解密方法
     * 专门针对64-256字节的数据进行优化
     *
     * @param encryptedData 加密后的字节数组
     * @return 原始字节数组
     */
    private byte[] decryptSmallBatch(byte[] encryptedData) {
        final int len = encryptedData.length;
        final byte kp1 = keyPart1;
        final byte kp2 = keyPart2;
        final int mask = shiftMask;

        // 批量处理以减少函数调用开销
        for (int i = 0; i < len; i++) {
            int dynamicShift = FastBlurUtils.getDynamicShift(i, mask);
            int b = encryptedData[i] & 0xFF;
            int xored1 = b ^ (kp2 & 0xFF);
            int shifted = rightShiftTable[dynamicShift][xored1] & 0xFF;
            encryptedData[i] = (byte) (shifted ^ (kp1 & 0xFF));
        }

        return encryptedData;
    }

    /**
     * Zero-copy加密ByteBuffer
     * 直接在ByteBuffer上进行操作，避免额外的内存分配
     *
     * @param buffer 包含原始数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
     */
    @Override
    public boolean encryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规加密方法
        return encrypt(buffer, offset, length);
    }

    /**
     * Zero-copy解密ByteBuffer
     * 直接在ByteBuffer上进行操作，避免额外的内存分配
     *
     * @param buffer 包含加密数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
     */
    @Override
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规解密方法
        return decrypt(buffer, offset, length);
    }

    /**
     * 并行加密字节数组（用于处理大数据块）
     *
     * <p>将数据分块并行处理，充分利用多核CPU优势</p>
     *
     * @param data 原始字节数组
     * @return 加密后字节数组
     */
    public byte[] encryptParallel(byte[] data) {
        return encryptParallel(data, customPool);
    }

    /**
     * Parallel encryption of byte array with custom ForkJoinPool.
     * <br/>
     * Splits data into chunks for parallel processing, fully utilizing multi-core CPU advantages.
     *
     * @param data the original byte array
     * @param pool the ForkJoinPool to use for parallel processing
     * @return the encrypted byte array
     * @see #encrypt(byte[])
     * @see EncryptTask
     */
    public byte[] encryptParallel(byte[] data, java.util.concurrent.ForkJoinPool pool) {
        if (data == null || data.length == 0) {
            return data;
        }

        // 创建数据副本以避免修改原始数据
        byte[] dataCopy = new byte[data.length];
        System.arraycopy(data, 0, dataCopy, 0, data.length);

        // 使用指定的ForkJoin框架进行并行处理
        pool.invoke(new EncryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask, leftShiftTable, rightShiftTable));

        return dataCopy;
    }

    /**
     * 并行解密字节数组（用于处理大数据块）
     *
     * <p>将数据分块并行处理，充分利用多核CPU优势</p>
     *
     * @param encryptedData 加密后的字节数组
     * @return 原始字节数组
     */
    public byte[] decryptParallel(byte[] encryptedData) {
        return decryptParallel(encryptedData, customPool);
    }

    /**
     * Parallel decryption of byte array with custom ForkJoinPool.
     * <br/>
     * Splits data into chunks for parallel processing, fully utilizing multi-core CPU advantages.
     *
     * @param encryptedData the encrypted byte array
     * @param pool the ForkJoinPool to use for parallel processing
     * @return the original byte array
     * @see #decrypt(byte[])
     * @see DecryptTask
     */
    public byte[] decryptParallel(byte[] encryptedData, java.util.concurrent.ForkJoinPool pool) {
        if (encryptedData == null || encryptedData.length == 0) {
            return encryptedData;
        }

        // 创建数据副本以避免修改原始数据
        byte[] dataCopy = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0, dataCopy, 0, encryptedData.length);

        // 使用指定的ForkJoin框架进行并行处理
        pool.invoke(new DecryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask, leftShiftTable, rightShiftTable));

        return dataCopy;
    }

    /**
     * 加密任务（用于并行处理）
     */
    private static class EncryptTask extends RecursiveAction {
        private static final int THRESHOLD = 16384; // 任务阈值：16KB
        private static final long serialVersionUID = 9130525864140232216L;
        private final byte[] data;
        private final int start;
        private final int end;
        private final byte keyPart1;
        private final byte keyPart2;
        private final int shiftMask;
        private final byte[][] leftShiftTable;
        private final byte[][] rightShiftTable;

        EncryptTask(byte[] data, int start, int end, byte keyPart1, byte keyPart2, int shiftMask,
                   byte[][] leftShiftTable, byte[][] rightShiftTable) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.keyPart1 = keyPart1;
            this.keyPart2 = keyPart2;
            this.shiftMask = shiftMask;
            this.leftShiftTable = leftShiftTable;
            this.rightShiftTable = rightShiftTable;
        }

        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);
                    int b = data[i] & 0xFF;
                    int xored1 = b ^ (keyPart1 & 0xFF);
                    int shifted = leftShiftTable[dynamicShift][xored1] & 0xFF;
                    data[i] = (byte) (shifted ^ (keyPart2 & 0xFF));
                }
            } else {
                // 分割任务
                int mid = (start + end) / 2;
                EncryptTask leftTask = new EncryptTask(data, start, mid, keyPart1, keyPart2, shiftMask, leftShiftTable, rightShiftTable);
                EncryptTask rightTask = new EncryptTask(data, mid, end, keyPart1, keyPart2, shiftMask, leftShiftTable, rightShiftTable);
                invokeAll(leftTask, rightTask);
            }
        }
    }

    /**
     * 解密任务（用于并行处理）
     */
    private static class DecryptTask extends RecursiveAction {
        private static final int THRESHOLD = 16384; // 任务阈值：16KB
        private static final long serialVersionUID = 8201094641149163487L;
        private final byte[] data;
        private final int start;
        private final int end;
        private final byte keyPart1;
        private final byte keyPart2;
        private final int shiftMask;
        private final byte[][] leftShiftTable;
        private final byte[][] rightShiftTable;

        DecryptTask(byte[] data, int start, int end, byte keyPart1, byte keyPart2, int shiftMask,
                   byte[][] leftShiftTable, byte[][] rightShiftTable) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.keyPart1 = keyPart1;
            this.keyPart2 = keyPart2;
            this.shiftMask = shiftMask;
            this.leftShiftTable = leftShiftTable;
            this.rightShiftTable = rightShiftTable;
        }

        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);
                    int b = data[i] & 0xFF;
                    int xored1 = b ^ (keyPart2 & 0xFF);
                    int shifted = rightShiftTable[dynamicShift][xored1] & 0xFF;
                    data[i] = (byte) (shifted ^ (keyPart1 & 0xFF));
                }
            } else {
                // 分割任务
                int mid = (start + end) / 2;
                DecryptTask leftTask = new DecryptTask(data, start, mid, keyPart1, keyPart2, shiftMask, leftShiftTable, rightShiftTable);
                DecryptTask rightTask = new DecryptTask(data, mid, end, keyPart1, keyPart2, shiftMask, leftShiftTable, rightShiftTable);
                invokeAll(leftTask, rightTask);
            }
        }
    }
}
