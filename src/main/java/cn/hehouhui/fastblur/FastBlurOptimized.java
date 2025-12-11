package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

/**
 * Simple lightweight obfuscation algorithm (optimized version).
 * <br/>
 * High-performance reversible lightweight encryption tool (supports fixed shift and 
 * dynamic shift enhanced obfuscation, security not guaranteed). Core: dynamic shift + 
 * XOR bitwise operations, extremely fast, reversible, obfuscation superior to fixed shift.
 *
 * <p>This class provides a simple data obfuscation mechanism that implements 
 * reversible data transformation through dynamic shift and XOR operations.
 * Compared to the original version, multiple performance optimizations have been made, 
 * suitable for lightweight data protection scenarios requiring extreme performance.</p>
 *
 * <p>Optimizations:
 * 1. Inline shift operations to avoid function call overhead
 * 2. Pre-compute key fragments to avoid repeated calculations
 * 3. Reduce unnecessary array copy operations
 * 4. Use bitwise operations instead of modulo operations
 * 5. Support both fixed shift and dynamic shift modes
 * </p>
 *
 * <p>Design Philosophy:
 * The optimized version focuses on reducing computational overhead through various 
 * micro-optimizations. It balances performance gains with code complexity to 
 * provide a good compromise between speed and maintainability.
 * </p>
 *
 * <p>Usage example:
 * <pre>{@code
 * FastBlurOptimized encryptor = new FastBlurOptimized();
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
 * @see FastBlurStrategy#MEMORY_FIRST
 */
public class FastBlurOptimized extends FastBlurBase {

    /**
     * Default constructor using UTF-8 character set encoding.
     * <br/>
     * Initializes a FastBlurOptimized instance with UTF-8 encoding and default 
     * configuration values. Dynamic shifting is enabled and parallel processing 
     * is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized();
     * }</pre>
     * </p>
     *
     * @see StandardCharsets#UTF_8
     */
    public FastBlurOptimized() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * Constructor initializing a FastBlurOptimized instance with the specified encoding.
     * <br/>
     * Initializes a FastBlurOptimized instance with the given character encoding and 
     * default key and shift values. Dynamic shifting is enabled and parallel processing 
     * is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding character encoding method
     * @see Charset
     */
    public FastBlurOptimized(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF), false);
    }

    /**
     * Constructor initializing a FastBlurOptimized instance with the specified encoding, 
     * key, and key segment (dynamic shift mode).
     * <br/>
     * Initializes a FastBlurOptimized instance in dynamic shift mode with the given 
     * parameters. Parallel processing is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding    character encoding method
     * @param key         64-bit key
     * @param keySegment  key segment value for dynamic shift calculation
     * @see Charset
     */
    public FastBlurOptimized(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, false);
    }

    /**
     * Constructor initializing a FastBlurOptimized instance with the specified encoding, 
     * key, key segment, and parallel processing option (dynamic shift mode).
     * <br/>
     * Initializes a FastBlurOptimized instance in dynamic shift mode with the given 
     * parameters. Parallel processing can be enabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
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
    public FastBlurOptimized(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        this(encoding, key, keySegment, true, parallelProcessing);
    }
    
    /**
     * Constructor initializing a FastBlurOptimized instance with the specified encoding, 
     * key, shift parameter, dynamic shift option, and parallel processing option.
     * <br/>
     * Fully configurable constructor for FastBlurOptimized instances.
     *
     * @param encoding           character encoding method
     * @param key                64-bit key (dynamic shift) or key for XOR operations (fixed shift)
     * @param shiftParam         key segment value (dynamic shift) or fixed shift value (fixed shift, 0-7)
     * @param dynamicShift       whether to enable dynamic shift
     * @param parallelProcessing whether to enable parallel processing
     * @see Charset
     * @see #dynamicShift
     * @see #parallelProcessing
     */
    public FastBlurOptimized(Charset encoding, long key, int shiftParam, boolean dynamicShift, boolean parallelProcessing) {
        super(encoding, parallelProcessing, dynamicShift,
              dynamicShift ? (byte) (key & 0xFF) : (byte) (key & 0xFF),
              dynamicShift ? (byte) ((key >> 8) & 0xFF) : (byte) 0,
              dynamicShift ? shiftParam & 0xFF : 0,
              dynamicShift ? 0 : shiftParam & 0x7);
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
     * 2. Apply dynamic circular left shift based on byte position
     * 3. XOR result with second key fragment ({@link #keyPart2})
     * 
     * In fixed shift mode:
     * 1. XOR data with the key ({@link #keyPart1})
     * 2. Apply fixed circular left shift ({@link #shift})
     * </p>
     *
     * <p>Performance Optimizations:
     * - For large data (≥16KB) with {@link #parallelProcessing} enabled, uses parallel processing
     * - For small data (≤128 bytes), uses unrolled loop optimization ({@link #encryptUnrolled(byte[])})
     * - Operates directly on input array to avoid memory copy overhead
     * - Inline shift operations to avoid function call overhead
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurOptimized encryptor = new FastBlurOptimized();
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
     * @see FastBlurUtils#rotateLeft(int, int)
     * @see FastBlurUtils#getDynamicShift(int, int)
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

        // 对于小数据(<=128字节)，使用展开循环优化
        if (data.length <= 128) {
            return encryptUnrolled(data);
        }

        if (dynamicShift) {
            // 动态位移模式
            // 直接在原数组上操作，避免数组复制开销
            for (int i = 0; i < data.length; i++) {
                int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);

                // 步骤1：第一段密钥异或
                data[i] ^= keyPart1;

                // 步骤2：动态循环左移（内联操作避免函数调用开销）
                if (dynamicShift != 0) {
                    int unsigned = data[i] & 0xFF;
                    int shifted = FastBlurUtils.rotateLeft(unsigned, dynamicShift);
                    data[i] = (byte) (shifted & 0xFF);
                }

                // 步骤3：第二段密钥异或
                data[i] ^= keyPart2;
            }
        } else {
            // 固定位移模式
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
     * Unrolled loop encryption method for small data.
     * <br/>
     * Specifically optimized for performance with small data (≤128 bytes).
     *
     * <p>Optimization Techniques:
     * <ul>
     *   <li>Loop unrolling to reduce branch prediction misses</li>
     *   <li>Local variable caching of frequently accessed fields</li>
     *   <li>Specialized handling for dynamic vs. fixed shift modes</li>
     *   <li>Processing 4 bytes at a time in the unrolled loop</li>
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
        final byte kp2 = keyPart2;
        final int mask = shiftMask;

        // 展开循环以减少分支开销
        int i = 0;
        for (; i <= len - 4; i += 4) {
            // 处理4个字节
            int dynamicShift0 = FastBlurUtils.getDynamicShift(i, mask);
            data[i] ^= kp1;
            if (dynamicShift0 != 0) {
                int unsigned = data[i] & 0xFF;
                data[i] = (byte) (FastBlurUtils.rotateLeft(unsigned, dynamicShift0) & 0xFF);
            }
            data[i] ^= kp2;

            int dynamicShift1 = FastBlurUtils.getDynamicShift(i + 1, mask);
            data[i+1] ^= kp1;
            if (dynamicShift1 != 0) {
                int unsigned = data[i+1] & 0xFF;
                data[i+1] = (byte) (FastBlurUtils.rotateLeft(unsigned, dynamicShift1) & 0xFF);
            }
            data[i+1] ^= kp2;

            int dynamicShift2 = FastBlurUtils.getDynamicShift(i + 2, mask);
            data[i+2] ^= kp1;
            if (dynamicShift2 != 0) {
                int unsigned = data[i+2] & 0xFF;
                data[i+2] = (byte) (FastBlurUtils.rotateLeft(unsigned, dynamicShift2) & 0xFF);
            }
            data[i+2] ^= kp2;

            int dynamicShift3 = FastBlurUtils.getDynamicShift(i + 3, mask);
            data[i+3] ^= kp1;
            if (dynamicShift3 != 0) {
                int unsigned = data[i+3] & 0xFF;
                data[i+3] = (byte) (FastBlurUtils.rotateLeft(unsigned, dynamicShift3) & 0xFF);
            }
            data[i+3] ^= kp2;
        }

        // 处理剩余字节
        for (; i < len; i++) {
            int dynamicShift = FastBlurUtils.getDynamicShift(i, mask);
            data[i] ^= kp1;
            if (dynamicShift != 0) {
                int unsigned = data[i] & 0xFF;
                data[i] = (byte) (FastBlurUtils.rotateLeft(unsigned, dynamicShift) & 0xFF);
            }
            data[i] ^= kp2;
        }

        return data;
    }

    /**
     * Decrypts a byte array (inverse of encryption, dynamic shift restoration).
     * <br/>
     * Decryption is the inverse operation of encryption, with steps in reverse order:
     * 1. XOR the data with the second part of the key (inverse of step 3)
     * 2. Perform dynamic circular right shift on the result (inverse of step 2)
     * 3. XOR the result with the first part of the key (inverse of step 1)
     *
     * <p>Algorithm Details (Inverse of encryption):
     * In dynamic shift mode:
     * 1. XOR data with second key fragment ({@link #keyPart2})
     * 2. Apply dynamic circular right shift based on byte position
     * 3. XOR result with first key fragment ({@link #keyPart1})
     * 
     * In fixed shift mode:
     * 1. Apply fixed circular right shift ({@link #shift})
     * 2. XOR data with the key ({@link #keyPart1})
     * </p>
     *
     * <p>Performance Optimizations:
     * - For large data (≥16KB) with {@link #parallelProcessing} enabled, uses parallel processing
     * - For small data (≤128 bytes), uses unrolled loop optimization ({@link #decryptUnrolled(byte[])})
     * - Operates directly on input array to avoid memory copy overhead
     * - Inline shift operations to avoid function call overhead
     * - Operations executed in reverse order compared to encryption
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurOptimized encryptor = new FastBlurOptimized();
     * byte[] encrypted = ...; // Previously encrypted byte array
     * byte[] decrypted = encryptor.decrypt(encrypted);
     * }
     * </pre>
     * </p>
     *
     * @param encryptedData the encrypted byte array
     * @return the original byte array (same array as input)
     * @throws IllegalArgumentException if the input data is malformed
     * @see #encrypt(byte[])
     * @see #dynamicShift
     * @see #parallelProcessing
     * @see FastBlurUtils#rotateRight(int, int)
     * @see FastBlurUtils#getDynamicShift(int, int)
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

        // 对于小数据(<=128字节)，使用展开循环优化
        if (encryptedData.length <= 128) {
            return decryptUnrolled(encryptedData);
        }

        if (dynamicShift) {
            // 动态位移模式
            // 直接在原数组上操作，避免数组复制开销
            for (int i = 0; i < encryptedData.length; i++) {
                int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);

                // 逆步骤3：第二段密钥异或还原
                encryptedData[i] ^= keyPart2;

                // 逆步骤2：动态循环右移（内联操作避免函数调用开销）
                if (dynamicShift != 0) {
                    int unsigned = encryptedData[i] & 0xFF;
                    int shifted = FastBlurUtils.rotateRight(unsigned, dynamicShift);
                    encryptedData[i] = (byte) (shifted & 0xFF);
                }

                // 逆步骤1：第一段密钥异或还原
                encryptedData[i] ^= keyPart1;
            }
        } else {
            // 固定位移模式
            // 直接在原数组上操作，避免数组复制开销
            for (int i = 0; i < encryptedData.length; i++) {
                // 逆步骤2：固定循环右移
                if (shift != 0) {
                    int unsigned = encryptedData[i] & 0xFF;
                    int shifted = FastBlurUtils.rotateRight(unsigned, shift);
                    encryptedData[i] = (byte) (shifted & 0xFF);
                }
                
                // 逆步骤1：密钥异或还原
                encryptedData[i] ^= keyPart1;
            }
        }
        return encryptedData;
    }

    /**
     * Unrolled loop decryption method for small data.
     * <br/>
     * Specifically optimized for performance with small data (≤128 bytes). 
     * Executes the inverse operations of {@link #encryptUnrolled(byte[])}.
     *
     * <p>Optimization Techniques:
     * <ul>
     *   <li>Loop unrolling to reduce branch prediction misses</li>
     *   <li>Local variable caching of frequently accessed fields</li>
     *   <li>Specialized handling for dynamic vs. fixed shift modes</li>
     *   <li>Processing 4 bytes at a time in the unrolled loop</li>
     *   <li>Operations executed in reverse order compared to encryption</li>
     * </ul>
     * </p>
     *
     * @param encryptedData the encrypted byte array
     * @return the decrypted byte array (same array as input)
     * @see #decrypt(byte[])
     * @see #dynamicShift
     * @see #encryptUnrolled(byte[])
     */
    private byte[] decryptUnrolled(byte[] encryptedData) {
        final int len = encryptedData.length;
        final byte kp1 = keyPart1;
        final byte kp2 = keyPart2;
        final int mask = shiftMask;

        // 展开循环以减少分支开销
        int i = 0;
        for (; i <= len - 4; i += 4) {
            // 处理4个字节（逆序执行加密的逆操作）
            int dynamicShift0 = FastBlurUtils.getDynamicShift(i, mask);
            encryptedData[i] ^= kp2;
            if (dynamicShift0 != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (FastBlurUtils.rotateRight(unsigned, dynamicShift0) & 0xFF);
            }
            encryptedData[i] ^= kp1;

            int dynamicShift1 = FastBlurUtils.getDynamicShift(i + 1, mask);
            encryptedData[i+1] ^= kp2;
            if (dynamicShift1 != 0) {
                int unsigned = encryptedData[i+1] & 0xFF;
                encryptedData[i+1] = (byte) (FastBlurUtils.rotateRight(unsigned, dynamicShift1) & 0xFF);
            }
            encryptedData[i+1] ^= kp1;

            int dynamicShift2 = FastBlurUtils.getDynamicShift(i + 2, mask);
            encryptedData[i+2] ^= kp2;
            if (dynamicShift2 != 0) {
                int unsigned = encryptedData[i+2] & 0xFF;
                encryptedData[i+2] = (byte) (FastBlurUtils.rotateRight(unsigned, dynamicShift2) & 0xFF);
            }
            encryptedData[i+2] ^= kp1;

            int dynamicShift3 = FastBlurUtils.getDynamicShift(i + 3, mask);
            encryptedData[i+3] ^= kp2;
            if (dynamicShift3 != 0) {
                int unsigned = encryptedData[i+3] & 0xFF;
                encryptedData[i+3] = (byte) (FastBlurUtils.rotateRight(unsigned, dynamicShift3) & 0xFF);
            }
            encryptedData[i+3] ^= kp1;
        }

        // 处理剩余字节
        for (; i < len; i++) {
            int dynamicShift = FastBlurUtils.getDynamicShift(i, mask);
            encryptedData[i] ^= kp2;
            if (dynamicShift != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (FastBlurUtils.rotateRight(unsigned, dynamicShift) & 0xFF);
            }
            encryptedData[i] ^= kp1;
        }

        return encryptedData;
    }

    /**
     * Parallel encryption of byte array (for processing large data blocks).
     * <br/>
     * Splits data into chunks for parallel processing, fully utilizing multi-core CPU advantages.
     *
     * <p>Parallel Processing Implementation:
     * - Uses {@link ForkJoinPool#commonPool()} to avoid frequent creation/destruction of thread pools
     * - Employs divide-and-conquer approach with {@link EncryptTask}
     * - Creates a copy of input data to avoid modifying the original
     * </p>
     *
     * <p>Thresholds:
     * - Parallel processing is triggered for data ≥16KB in {@link #encrypt(byte[])}
     * - Task splitting threshold is 16KB in {@link EncryptTask}
     * </p>
     *
     * @param data the original byte array
     * @return the encrypted byte array
     * @see #encrypt(byte[])
     * @see EncryptTask
     * @see ForkJoinPool#commonPool()
     */
    public byte[] encryptParallel(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }

        // 创建数据副本以避免修改原始数据
        byte[] dataCopy = new byte[data.length];
        System.arraycopy(data, 0, dataCopy, 0, data.length);

        // 使用ForkJoin框架进行并行处理
        // 使用公共ForkJoin框架进行并行处理，避免频繁创建销毁线程池
        ForkJoinPool.commonPool().invoke(new EncryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask));

        return dataCopy;
    }

    /**
     * Parallel decryption of byte array (for processing large data blocks).
     * <br/>
     * Splits data into chunks for parallel processing, fully utilizing multi-core CPU advantages.
     *
     * <p>Parallel Processing Implementation:
     * - Uses {@link ForkJoinPool#commonPool()} to avoid frequent creation/destruction of thread pools
     * - Employs divide-and-conquer approach with {@link DecryptTask}
     * - Creates a copy of input data to avoid modifying the original
     * </p>
     *
     * <p>Thresholds:
     * - Parallel processing is triggered for data ≥16KB in {@link #decrypt(byte[])}
     * - Task splitting threshold is 16KB in {@link DecryptTask}
     * </p>
     *
     * @param encryptedData the encrypted byte array
     * @return the original byte array
     * @see #decrypt(byte[])
     * @see DecryptTask
     * @see ForkJoinPool#commonPool()
     */
    public byte[] decryptParallel(byte[] encryptedData) {
        if (encryptedData == null || encryptedData.length == 0) {
            return encryptedData;
        }

        // 创建数据副本以避免修改原始数据
        byte[] dataCopy = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0, dataCopy, 0, encryptedData.length);

        // 使用ForkJoin框架进行并行处理
        // 使用公共ForkJoin框架进行并行处理，避免频繁创建销毁线程池
        ForkJoinPool.commonPool().invoke(new DecryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask));

        return dataCopy;
    }

    /**
     * Zero-copy encryption of ByteBuffer.
     * <br/>
     * Operates directly on the ByteBuffer to avoid additional memory allocation.
     *
     * <p>Implementation:
     * This implementation falls back to the regular encryption method. Subclasses 
     * that can work directly with ByteBuffers should override this method for 
     * improved performance.
     * </p>
     *
     * @param buffer the direct buffer containing the original data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #encrypt(ByteBuffer, int, int)
     * @see ByteBuffer#isDirect()
     */
    @Override
    public boolean encryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规加密方法
        return encrypt(buffer, offset, length);
    }

    /**
     * Zero-copy decryption of ByteBuffer.
     * <br/>
     * Operates directly on the ByteBuffer to avoid additional memory allocation.
     *
     * <p>Implementation:
     * This implementation falls back to the regular decryption method. Subclasses 
     * that can work directly with ByteBuffers should override this method for 
     * improved performance.
     * </p>
     *
     * @param buffer the direct buffer containing the encrypted data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #decrypt(ByteBuffer, int, int)
     * @see ByteBuffer#isDirect()
     */
    @Override
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规解密方法
        return decrypt(buffer, offset, length);
    }

    /**
     * Encryption task for parallel processing.
     * <br/>
     * A RecursiveAction that handles encryption of a data segment in parallel. 
     * Processes data segments smaller than the threshold directly, and splits 
     * larger segments into subtasks.
     *
     * <p>Parallel Processing Strategy:
     * - Threshold: 16KB data segments
     * - Work splitting: Divides large segments in half recursively
     * - Processing: Direct encryption of small segments
     * </p>
     *
     * @see RecursiveAction
     * @see #encryptParallel(byte[])
     */
    private static class EncryptTask extends RecursiveAction {
        /**
         * Task threshold: 16KB.
         * <br/>
         * Data segments smaller than this threshold are processed directly. 
         * Larger segments are split into subtasks.
         */
        private static final int THRESHOLD = 16384; // 任务阈值：16KB
        
        private static final long serialVersionUID = -5048830231452146650L;
        
        /**
         * Data to be encrypted.
         * <br/>
         * Reference to the shared data array being processed by all tasks.
         */
        private final byte[] data;
        
        /**
         * Start index of the data segment to process.
         * <br/>
         * Inclusive start index within the data array.
         */
        private final int start;
        
        /**
         * End index of the data segment to process.
         * <br/>
         * Exclusive end index within the data array.
         */
        private final int end;
        
        /**
         * First key fragment for XOR operations.
         * <br/>
         * The first part of a split-key approach where the key is divided 
         * into multiple parts that are applied at different stages of the encryption 
         * process.
         *
         * @see FastBlurOptimized#keyPart1
         */
        private final byte keyPart1;
        
        /**
         * Second key fragment for XOR operations.
         * <br/>
         * The second part of a split-key approach. In dynamic shift mode, 
         * this is applied after the shift operation, providing a form of double 
         * encryption for each byte.
         *
         * @see FastBlurOptimized#keyPart2
         */
        private final byte keyPart2;
        
        /**
         * Mask used for shift calculation.
         * <br/>
         * In dynamic shift mode, this mask is used in conjunction with the byte 
         * position to calculate the specific shift amount for each byte.
         *
         * @see FastBlurOptimized#shiftMask
         * @see FastBlurUtils#getDynamicShift(int, int)
         */
        private final int shiftMask;

        /**
         * Constructs an EncryptTask for a data segment.
         * <br/>
         * Initializes a task to encrypt a segment of a byte array using the 
         * specified key and shift parameters.
         *
         * @param data      the data array to process
         * @param start     the start index of the segment
         * @param end       the end index of the segment
         * @param keyPart1  the first key fragment for XOR operations
         * @param keyPart2  the second key fragment for XOR operations
         * @param shiftMask the mask used for shift calculation
         */
        EncryptTask(byte[] data, int start, int end, byte keyPart1, byte keyPart2, int shiftMask) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.keyPart1 = keyPart1;
            this.keyPart2 = keyPart2;
            this.shiftMask = shiftMask;
        }

        /**
         * Computes the encryption task.
         * <br/>
         * Processes data segments smaller than the threshold directly, or splits 
         * larger segments into subtasks for parallel processing.
         *
         * <p>Algorithm:
         * For each byte in the segment:
         * 1. XOR with first key fragment ({@link #keyPart1})
         * 2. Apply dynamic circular left shift if shift != 0
         * 3. XOR with second key fragment ({@link #keyPart2})
         * </p>
         *
         * @see RecursiveAction#compute()
         * @see FastBlurUtils#rotateLeft(int, int)
         * @see FastBlurUtils#getDynamicShift(int, int)
         */
        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);

                    // 步骤1：第一段密钥异或
                    data[i] ^= keyPart1;

                    // 步骤2：动态循环左移
                    if (dynamicShift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = FastBlurUtils.rotateLeft(unsigned, dynamicShift);
                        data[i] = (byte) (shifted & 0xFF);
                    }

                    // 步骤3：第二段密钥异或
                    data[i] ^= keyPart2;
                }
            } else {
                // 分割任务
                int mid = (start + end) / 2;
                EncryptTask leftTask = new EncryptTask(data, start, mid, keyPart1, keyPart2, shiftMask);
                EncryptTask rightTask = new EncryptTask(data, mid, end, keyPart1, keyPart2, shiftMask);
                invokeAll(leftTask, rightTask);
            }
        }
    }

    /**
     * Decryption task for parallel processing.
     * <br/>
     * A RecursiveAction that handles decryption of a data segment in parallel. 
     * Processes data segments smaller than the threshold directly, and splits 
     * larger segments into subtasks.
     *
     * <p>Parallel Processing Strategy:
     * - Threshold: 16KB data segments
     * - Work splitting: Divides large segments in half recursively
     * - Processing: Direct decryption of small segments
     * </p>
     *
     * @see RecursiveAction
     * @see #decryptParallel(byte[])
     */
    private static class DecryptTask extends RecursiveAction {
        /**
         * Task threshold: 16KB.
         * <br/>
         * Data segments smaller than this threshold are processed directly. 
         * Larger segments are split into subtasks.
         */
        private static final int THRESHOLD = 16384; // 任务阈值：16KB
        
        private static final long serialVersionUID = 4586245996695330434L;
        
        /**
         * Data to be decrypted.
         * <br/>
         * Reference to the shared data array being processed by all tasks.
         */
        private final byte[] data;
        
        /**
         * Start index of the data segment to process.
         * <br/>
         * Inclusive start index within the data array.
         */
        private final int start;
        
        /**
         * End index of the data segment to process.
         * <br/>
         * Exclusive end index within the data array.
         */
        private final int end;
        
        /**
         * First key fragment for XOR operations.
         * <br/>
         * The first part of a split-key approach where the key is divided 
         * into multiple parts that are applied at different stages of the decryption 
         * process.
         *
         * @see FastBlurOptimized#keyPart1
         */
        private final byte keyPart1;
        
        /**
         * Second key fragment for XOR operations.
         * <br/>
         * The second part of a split-key approach. In dynamic shift mode, 
         * this is applied before the shift operation during decryption.
         *
         * @see FastBlurOptimized#keyPart2
         */
        private final byte keyPart2;
        
        /**
         * Mask used for shift calculation.
         * <br/>
         * In dynamic shift mode, this mask is used in conjunction with the byte 
         * position to calculate the specific shift amount for each byte.
         *
         * @see FastBlurOptimized#shiftMask
         * @see FastBlurUtils#getDynamicShift(int, int)
         */
        private final int shiftMask;

        /**
         * Constructs a DecryptTask for a data segment.
         * <br/>
         * Initializes a task to decrypt a segment of a byte array using the 
         * specified key and shift parameters.
         *
         * @param data      the data array to process
         * @param start     the start index of the segment
         * @param end       the end index of the segment
         * @param keyPart1  the first key fragment for XOR operations
         * @param keyPart2  the second key fragment for XOR operations
         * @param shiftMask the mask used for shift calculation
         */
        DecryptTask(byte[] data, int start, int end, byte keyPart1, byte keyPart2, int shiftMask) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.keyPart1 = keyPart1;
            this.keyPart2 = keyPart2;
            this.shiftMask = shiftMask;
        }

        /**
         * Computes the decryption task.
         * <br/>
         * Processes data segments smaller than the threshold directly, or splits 
         * larger segments into subtasks for parallel processing.
         *
         * <p>Algorithm (Inverse of encryption):
         * For each byte in the segment:
         * 1. XOR with second key fragment ({@link #keyPart2})
         * 2. Apply dynamic circular right shift if shift != 0
         * 3. XOR with first key fragment ({@link #keyPart1})
         * </p>
         *
         * <p>Note: Operations are performed in reverse order compared to encryption.
         * </p>
         *
         * @see RecursiveAction#compute()
         * @see FastBlurUtils#rotateRight(int, int)
         * @see FastBlurUtils#getDynamicShift(int, int)
         */
        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);

                    // 逆步骤3：第二段密钥异或还原
                    data[i] ^= keyPart2;

                    // 逆步骤2：动态循环右移
                    if (dynamicShift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = FastBlurUtils.rotateRight(unsigned, dynamicShift);
                        data[i] = (byte) (shifted & 0xFF);
                    }

                    // 逆步骤1：第一段密钥异或还原
                    data[i] ^= keyPart1;
                }
            } else {
                // 分割任务
                int mid = (start + end) / 2;
                DecryptTask leftTask = new DecryptTask(data, start, mid, keyPart1, keyPart2, shiftMask);
                DecryptTask rightTask = new DecryptTask(data, mid, end, keyPart1, keyPart2, shiftMask);
                invokeAll(leftTask, rightTask);
            }
        }
    }
}