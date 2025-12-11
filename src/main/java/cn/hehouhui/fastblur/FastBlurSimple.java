package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

/**
 * Simple lightweight obfuscation algorithm (simplified version).
 * <br/>
 * High-performance reversible lightweight encryption tool (supports fixed shift and 
 * dynamic shift enhanced obfuscation, security not guaranteed). Core: fixed shift/
 * dynamic shift + XOR bitwise operations, extremely fast, reversible, obfuscation 
 * superior to fixed shift.
 * 
 * <p>This class provides a simple data obfuscation mechanism that implements 
 * reversible data transformation through fixed shift/dynamic shift and XOR operations. 
 * Compared to complex versions, the algorithm has been simplified for lightweight 
 * data protection scenarios requiring extreme performance.</p>
 * 
 * <p>Simplification optimizations:
 * 1. Supports both fixed shift and dynamic shift modes
 * 2. Reduces encryption steps, performing only one XOR and one shift operation
 * 3. Supports parallel processing of large data blocks
 * </p>
 *
 * <p>Design Philosophy:
 * FastBlurSimple is designed for scenarios where maximum performance is needed 
 * with minimal computational overhead. It trades some obfuscation strength for 
 * speed by reducing the number of transformation steps.
 * </p>
 *
 * <p>Usage example:
 * <pre>{@code
 * FastBlurSimple encryptor = new FastBlurSimple();
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
public class FastBlurSimple extends FastBlurBase {

    /**
     * Default constructor using UTF-8 character set encoding.
     * <br/>
     * Initializes a FastBlurSimple instance with UTF-8 encoding and default 
     * configuration values. Both dynamic shifting and parallel processing are disabled.
     * 
     * <p>Usage example:
     * <pre>{@code
     * FastBlurSimple blur = new FastBlurSimple();
     * }</pre>
     * </p>
     *
     * @see StandardCharsets#UTF_8
     */
    public FastBlurSimple() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * Constructor initializing a FastBlurSimple instance with the specified encoding.
     * <br/>
     * Initializes a FastBlurSimple instance with the given character encoding and 
     * default key and shift values. Both dynamic shifting and parallel processing 
     * are disabled.
     * 
     * <p>Usage example:
     * <pre>{@code
     * FastBlurSimple blur = new FastBlurSimple(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding character encoding method
     * @see Charset
     */
    public FastBlurSimple(Charset encoding) {
        this(encoding, (byte) 0xAB, 3, false, false);
    }

    /**
     * Constructor initializing a FastBlurSimple instance with the specified encoding, 
     * key, and shift value (fixed shift mode).
     * <br/>
     * Initializes a FastBlurSimple instance in fixed shift mode with the given 
     * parameters. Dynamic shifting and parallel processing are disabled.
     * 
     * <p>Usage example:
     * <pre>{@code
     * FastBlurSimple blur = new FastBlurSimple(StandardCharsets.UTF_8, (byte) 0xCD, 5);
     * }</pre>
     * </p>
     *
     * @param encoding character encoding method
     * @param key      key for XOR operations
     * @param shift    fixed shift value (between 0-7)
     * @see Charset
     */
    public FastBlurSimple(Charset encoding, byte key, int shift) {
        this(encoding, key, shift, false, false);
    }
    
    /**
     * Constructor initializing a FastBlurSimple instance with the specified encoding, 
     * key, shift value, and dynamic shift option.
     * <br/>
     * Initializes a FastBlurSimple instance with the given parameters. Parallel 
     * processing is disabled.
     * 
     * @param encoding      character encoding method
     * @param key           key for XOR operations
     * @param shift         fixed shift value (0-7) or key segment value (for dynamic shift)
     * @param dynamicShift  whether to enable dynamic shifting
     * @see Charset
     * @see #dynamicShift
     */
    public FastBlurSimple(Charset encoding, byte key, int shift, boolean dynamicShift) {
        this(encoding, key, shift, dynamicShift, false);
    }

    /**
     * Constructor initializing a FastBlurSimple instance with the specified encoding, 
     * key, shift value, dynamic shift option, and parallel processing option.
     * <br/>
     * Fully configurable constructor for FastBlurSimple instances.
     * 
     * @param encoding          character encoding method
     * @param key               key for XOR operations
     * @param shift             fixed shift value (0-7) or key segment value (for dynamic shift)
     * @param dynamicShift      whether to enable dynamic shifting
     * @param parallelProcessing whether to enable parallel processing
     * @see Charset
     * @see #dynamicShift
     * @see #parallelProcessing
     */
    public FastBlurSimple(Charset encoding, byte key, int shift, boolean dynamicShift, boolean parallelProcessing) {
        super(encoding, parallelProcessing, dynamicShift, 
              dynamicShift ? key : key, 
              dynamicShift ? (byte) ((key + shift) & 0xFF) : (byte) 0, 
              dynamicShift ? shift & 0xFF : 0, 
              dynamicShift ? 0 : shift & 0x7);
    }
    
    /**
     * Simplified encryption of byte array (supports fixed shift and dynamic shift enhanced obfuscation).
     * <br/>
     * Simplified encryption process consists of only two steps:
     * 1. XOR the data with the key
     * 2. Perform fixed circular left shift or dynamic circular left shift on the result
     *
     * <p>Algorithm Details:
     * In dynamic shift mode, the process involves three steps:
     * 1. XOR data with first key fragment ({@link #keyPart1})
     * 2. Apply dynamic circular left shift based on byte position
     * 3. XOR result with second key fragment ({@link #keyPart2})
     * 
     * In fixed shift mode, the process involves two steps:
     * 1. XOR data with the key ({@link #keyPart1})
     * 2. Apply fixed circular left shift ({@link #shift})
     * </p>
     *
     * <p>Performance Optimizations:
     * - For small data (≤128 bytes), uses unrolled loop optimization
     * - For large data with {@link #parallelProcessing} enabled, uses parallel processing
     * - Operates directly on the input array to avoid memory copy overhead
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurSimple encryptor = new FastBlurSimple();
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

        // 根据配置决定是否使用并行处理
        if (parallelProcessing && data.length >= 8192) {
            return encryptParallel(data);
        }

        // 对于小数据(<=128字节)，使用展开循环优化
        if (data.length <= 128) {
            return encryptUnrolled(data);
        }

        // 直接在原数组上操作，避免数组复制开销
        if (dynamicShift) {
            // 动态位移模式
            for (int i = 0; i < data.length; i++) {
                // 步骤1：第一段密钥异或
                data[i] ^= keyPart1;

                // 步骤2：动态循环左移
                int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);
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
     * Specifically optimized for performance with small data (≤128 bytes). This 
     * method uses loop unrolling to reduce branching overhead and improve 
     * execution speed.
     *
     * <p>Optimization Techniques:
     * <ul>
     *   <li>Loop unrolling to reduce branch prediction misses</li>
     *   <li>Local variable caching of frequently accessed fields</li>
     *   <li>Specialized handling for dynamic vs. fixed shift modes</li>
     * </ul>
     * </p>
     *
     * <p>In dynamic shift mode, processes 4 bytes at a time in the unrolled loop. 
     * In fixed shift mode, processes 8 bytes at a time for even better performance 
     * with simple operations.
     * </p>
     *
     * @param data the original byte array
     * @return the encrypted byte array (same array as input)
     * @see #encrypt(byte[])
     * @see #dynamicShift
     */
    private byte[] encryptUnrolled(byte[] data) {
        final int len = data.length;
        
        if (dynamicShift) {
            // 动态位移模式
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
        } else {
            // 固定位移模式
            // 展开循环以减少分支开销
            int i = 0;
            for (; i <= len - 8; i += 8) {
                // 处理8个字节
                data[i] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i] & 0xFF;
                    data[i] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
                
                data[i+1] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i+1] & 0xFF;
                    data[i+1] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
                
                data[i+2] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i+2] & 0xFF;
                    data[i+2] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
                
                data[i+3] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i+3] & 0xFF;
                    data[i+3] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
                
                data[i+4] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i+4] & 0xFF;
                    data[i+4] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
                
                data[i+5] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i+5] & 0xFF;
                    data[i+5] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
                
                data[i+6] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i+6] & 0xFF;
                    data[i+6] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
                
                data[i+7] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i+7] & 0xFF;
                    data[i+7] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
            }
            
            // 处理剩余字节
            for (; i < len; i++) {
                data[i] ^= keyPart1;
                if (shift != 0) {
                    int unsigned = data[i] & 0xFF;
                    data[i] = (byte) (FastBlurUtils.rotateLeft(unsigned, shift) & 0xFF);
                }
            }
        }
        
        return data;
    }

    /**
     * Simplified decryption of byte array (inverse of encryption, supports fixed shift and dynamic shift restoration).
     * <br/>
     * Simplified decryption is the inverse operation of encryption:
     * 1. Perform fixed circular right shift or dynamic circular right shift on data
     * 2. XOR the data with the key
     *
     * <p>Algorithm Details:
     * In dynamic shift mode, the process is the reverse of encryption:
     * 1. XOR data with second key fragment ({@link #keyPart2})
     * 2. Apply dynamic circular right shift based on byte position
     * 3. XOR result with first key fragment ({@link #keyPart1})
     * 
     * In fixed shift mode, the process is:
     * 1. Apply fixed circular right shift ({@link #shift})
     * 2. XOR data with the key ({@link #keyPart1})
     * </p>
     *
     * <p>Performance Optimizations:
     * - For small data (≤128 bytes), uses unrolled loop optimization
     * - For large data with {@link #parallelProcessing} enabled, uses parallel processing
     * - Operates directly on the input array to avoid memory copy overhead
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurSimple encryptor = new FastBlurSimple();
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

        // 根据配置决定是否使用并行处理
        if (parallelProcessing && encryptedData.length >= 8192) {
            return decryptParallel(encryptedData);
        }

        // 对于小数据(<=128字节)，使用展开循环优化
        if (encryptedData.length <= 128) {
            return decryptUnrolled(encryptedData);
        }

        // 直接在原数组上操作，避免数组复制开销
        if (dynamicShift) {
            // 动态位移模式
            for (int i = 0; i < encryptedData.length; i++) {
                // 逆步骤3：第二段密钥异或还原
                encryptedData[i] ^= keyPart2;

                // 逆步骤2：动态循环右移
                int dynamicShift = FastBlurUtils.getDynamicShift(i, shiftMask);
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
            for (int i = 0; i < encryptedData.length; i++) {
                // 逆步骤2：固定循环右移
                if (shift != 0) {
                    int unsigned = encryptedData[i] & 0xFF;
                    int shifted = FastBlurUtils.rotateRight(unsigned, shift);
                    encryptedData[i] = (byte) (shifted & 0xFF);
                }
                
                // 逆步骤1：密钥异或
                encryptedData[i] ^= keyPart1;
            }
        }
        return encryptedData;
    }

    /**
     * Unrolled loop decryption method for small data.
     * <br/>
     * Specifically optimized for performance with small data (≤128 bytes). This 
     * method uses loop unrolling to reduce branching overhead and improve 
     * execution speed. Executes the inverse operations of {@link #encryptUnrolled(byte[])}.
     *
     * <p>Optimization Techniques:
     * <ul>
     *   <li>Loop unrolling to reduce branch prediction misses</li>
     *   <li>Local variable caching of frequently accessed fields</li>
     *   <li>Specialized handling for dynamic vs. fixed shift modes</li>
     *   <li>Operations executed in reverse order compared to encryption</li>
     * </ul>
     * </p>
     *
     * <p>In dynamic shift mode, processes 4 bytes at a time in the unrolled loop. 
     * In fixed shift mode, processes 8 bytes at a time for even better performance 
     * with simple operations.
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
        
        if (dynamicShift) {
            // 动态位移模式
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
        } else {
            // 固定位移模式
            // 展开循环以减少分支开销
            int i = 0;
            for (; i <= len - 8; i += 8) {
                // 处理8个字节
                if (shift != 0) {
                    int unsigned = encryptedData[i] & 0xFF;
                    encryptedData[i] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i] ^= keyPart1;
                
                if (shift != 0) {
                    int unsigned = encryptedData[i+1] & 0xFF;
                    encryptedData[i+1] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i+1] ^= keyPart1;
                
                if (shift != 0) {
                    int unsigned = encryptedData[i+2] & 0xFF;
                    encryptedData[i+2] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i+2] ^= keyPart1;
                
                if (shift != 0) {
                    int unsigned = encryptedData[i+3] & 0xFF;
                    encryptedData[i+3] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i+3] ^= keyPart1;
                
                if (shift != 0) {
                    int unsigned = encryptedData[i+4] & 0xFF;
                    encryptedData[i+4] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i+4] ^= keyPart1;
                
                if (shift != 0) {
                    int unsigned = encryptedData[i+5] & 0xFF;
                    encryptedData[i+5] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i+5] ^= keyPart1;
                
                if (shift != 0) {
                    int unsigned = encryptedData[i+6] & 0xFF;
                    encryptedData[i+6] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i+6] ^= keyPart1;
                
                if (shift != 0) {
                    int unsigned = encryptedData[i+7] & 0xFF;
                    encryptedData[i+7] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i+7] ^= keyPart1;
            }
            
            // 处理剩余字节
            for (; i < len; i++) {
                if (shift != 0) {
                    int unsigned = encryptedData[i] & 0xFF;
                    encryptedData[i] = (byte) (FastBlurUtils.rotateRight(unsigned, shift) & 0xFF);
                }
                encryptedData[i] ^= keyPart1;
            }
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
     * - Parallel processing is triggered for data ≥8KB in {@link #encrypt(ByteBuffer, int, int)}
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
        
        // 使用公共ForkJoin框架进行并行处理，避免频繁创建销毁线程池
        ForkJoinPool pool = ForkJoinPool.commonPool();
        pool.invoke(new EncryptTask(dataCopy, 0, dataCopy.length, keyPart1, shift));
        
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
     * - Parallel processing is triggered for data ≥8KB in {@link #decrypt(ByteBuffer, int, int)}
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
        
        // 使用公共ForkJoin框架进行并行处理，避免频繁创建销毁线程池
        ForkJoinPool pool = ForkJoinPool.commonPool();
        pool.invoke(new DecryptTask(dataCopy, 0, dataCopy.length, keyPart1, shift));
        
        return dataCopy;
    }

    /**
     * Encrypts a ByteBuffer (optional implementation).
     * <br/>
     * Encrypts data in a direct ByteBuffer. For large data with {@link #parallelProcessing} 
     * enabled, uses parallel processing. Otherwise performs serial processing directly 
     * on the buffer to avoid memory allocation.
     *
     * <p>Processing Logic:
     * - For very large data (≥32KB) with parallel processing enabled, uses parallel encryption
     * - For medium data with parallel processing enabled (≥8KB), uses parallel encryption
     * - For small data, performs direct in-buffer encryption
     * </p>
     *
     * @param buffer the direct buffer containing the original data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #encryptZeroCopy(ByteBuffer, int, int)
     * @see #encryptParallel(byte[])
     * @see ByteBuffer#isDirect()
     */
    @Override
    public boolean encrypt(ByteBuffer buffer, int offset, int length) {
        if (buffer == null || !buffer.isDirect() || length <= 0) {
            return false;
        }

        // 如果启用了并行处理且数据足够大，则使用并行处理
        if (parallelProcessing && length >= 32768) {
            byte[] temp = new byte[length];
            buffer.position(offset);
            buffer.get(temp);
            byte[] encrypted = encryptParallel(temp);
            buffer.position(offset);
            buffer.put(encrypted);
            return true;
        }

        // 否则使用串行处理
        for (int i = offset; i < offset + length; i++) {
            byte b = buffer.get(i);
            b ^= keyPart1;
            if (shift != 0) {
                int unsigned = b & 0xFF;
                int shifted = FastBlurUtils.rotateLeft(unsigned, shift);
                b = (byte) (shifted & 0xFF);
            }
            buffer.put(i, b);
        }
        return true;
    }

    /**
     * Zero-copy encryption of ByteBuffer.
     * <br/>
     * Operates directly on the ByteBuffer to avoid additional memory allocation. 
     * For large data with {@link #parallelProcessing} enabled, uses parallel processing. 
     * Otherwise performs serial processing directly on the buffer.
     *
     * <p>Difference from {@link #encrypt(ByteBuffer, int, int)}:
     * - Lower threshold for parallel processing (8KB vs 32KB)
     * - More aggressive in using parallel processing for zero-copy operations
     * </p>
     *
     * @param buffer the direct buffer containing the original data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #encrypt(ByteBuffer, int, int)
     * @see #encryptParallel(byte[])
     * @see ByteBuffer#isDirect()
     */
    @Override
    public boolean encryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        if (buffer == null || !buffer.isDirect() || length <= 0) {
            return false;
        }

        // 如果启用了并行处理且数据足够大，则使用并行处理
        if (parallelProcessing && length >= 8192) {
            byte[] temp = new byte[length];
            buffer.position(offset);
            buffer.get(temp);
            byte[] encrypted = encryptParallel(temp);
            buffer.position(offset);
            buffer.put(encrypted);
            return true;
        }

        // 否则使用串行处理
        for (int i = offset; i < offset + length; i++) {
            byte b = buffer.get(i);
            b ^= keyPart1;
            if (shift != 0) {
                int unsigned = b & 0xFF;
                int shifted = FastBlurUtils.rotateLeft(unsigned, shift);
                b = (byte) (shifted & 0xFF);
            }
            buffer.put(i, b);
        }
        return true;
    }

    /**
     * Decrypts a ByteBuffer (optional implementation).
     * <br/>
     * Decrypts data in a direct ByteBuffer. For large data with {@link #parallelProcessing} 
     * enabled, uses parallel processing. Otherwise performs serial processing directly 
     * on the buffer to avoid memory allocation.
     *
     * <p>Processing Logic:
     * - For large data (≥8KB) with parallel processing enabled, uses parallel decryption
     * - For small data, performs direct in-buffer decryption
     * </p>
     *
     * <p>Algorithm Details:
     * The decryption process is the inverse of the encryption process:
     * 1. Apply fixed circular right shift ({@link #shift})
     * 2. XOR data with the key ({@link #keyPart1})
     * </p>
     *
     * @param buffer the direct buffer containing the encrypted data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #decryptZeroCopy(ByteBuffer, int, int)
     * @see #decryptParallel(byte[])
     * @see ByteBuffer#isDirect()
     */
    @Override
    public boolean decrypt(ByteBuffer buffer, int offset, int length) {
        if (buffer == null || !buffer.isDirect() || length <= 0) {
            return false;
        }

        // 如果启用了并行处理且数据足够大，则使用并行处理
        if (parallelProcessing && length >= 8192) {
            byte[] temp = new byte[length];
            buffer.position(offset);
            buffer.get(temp);
            byte[] decrypted = decryptParallel(temp);
            buffer.position(offset);
            buffer.put(decrypted);
            return true;
        }

        // 否则使用串行处理
        for (int i = offset; i < offset + length; i++) {
            byte b = buffer.get(i);
            if (shift != 0) {
                int unsigned = b & 0xFF;
                int shifted = FastBlurUtils.rotateRight(unsigned, shift);
                b = (byte) (shifted & 0xFF);
            }
            b ^= keyPart1;
            buffer.put(i, b);
        }
        return true;
    }

    /**
     * Zero-copy decryption of ByteBuffer.
     * <br/>
     * Operates directly on the ByteBuffer to avoid additional memory allocation. 
     * For large data with {@link #parallelProcessing} enabled, uses parallel processing. 
     * Otherwise performs serial processing directly on the buffer.
     *
     * <p>Behavior:
     * Functions identically to {@link #decrypt(ByteBuffer, int, int)} for ByteBuffer 
     * decryption, but named differently to indicate the zero-copy nature of the operation.
     * </p>
     *
     * @param buffer the direct buffer containing the encrypted data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #decrypt(ByteBuffer, int, int)
     * @see #decryptParallel(byte[])
     * @see ByteBuffer#isDirect()
     */
    @Override
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        if (buffer == null || !buffer.isDirect() || length <= 0) {
            return false;
        }

        // 如果启用了并行处理且数据足够大，则使用并行处理
        if (parallelProcessing && length >= 8192) {
            byte[] temp = new byte[length];
            buffer.position(offset);
            buffer.get(temp);
            byte[] decrypted = decryptParallel(temp);
            buffer.position(offset);
            buffer.put(decrypted);
            return true;
        }

        // 否则使用串行处理
        for (int i = offset; i < offset + length; i++) {
            byte b = buffer.get(i);
            if (shift != 0) {
                int unsigned = b & 0xFF;
                int shifted = FastBlurUtils.rotateRight(unsigned, shift);
                b = (byte) (shifted & 0xFF);
            }
            b ^= keyPart1;
            buffer.put(i, b);
        }
        return true;
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
        
        private static final long serialVersionUID = -1180001722974992448L;
        
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
         * Key for XOR operations.
         * <br/>
         * The key fragment used for XOR operations in fixed shift mode.
         *
         * @see FastBlurSimple#keyPart1
         */
        private final byte key;
        
        /**
         * Fixed shift value.
         * <br/>
         * The shift amount used in fixed shift mode.
         *
         * @see FastBlurSimple#shift
         */
        private final int shift;

        /**
         * Constructs an EncryptTask for a data segment.
         * <br/>
         * Initializes a task to encrypt a segment of a byte array using the 
         * specified key and shift parameters.
         *
         * @param data  the data array to process
         * @param start the start index of the segment
         * @param end   the end index of the segment
         * @param key   the key for XOR operations
         * @param shift the shift value for shift operations
         */
        EncryptTask(byte[] data, int start, int end, byte key, int shift) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.key = key;
            this.shift = shift;
        }

        /**
         * Computes the encryption task.
         * <br/>
         * Processes data segments smaller than the threshold directly, or splits 
         * larger segments into subtasks for parallel processing.
         *
         * <p>Algorithm:
         * For each byte in the segment:
         * 1. XOR with the key
         * 2. Apply fixed circular left shift if shift != 0
         * </p>
         *
         * @see RecursiveAction#compute()
         * @see FastBlurUtils#rotateLeft(int, int)
         */
        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    data[i] ^= key;
                    if (shift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = FastBlurUtils.rotateLeft(unsigned, shift);
                        data[i] = (byte) (shifted & 0xFF);
                    }
                }
            } else {
                // 分割任务
                int mid = (start + end) / 2;
                EncryptTask leftTask = new EncryptTask(data, start, mid, key, shift);
                EncryptTask rightTask = new EncryptTask(data, mid, end, key, shift);
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
        
        private static final long serialVersionUID = -4052727379621115969L;
        
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
         * Key for XOR operations.
         * <br/>
         * The key fragment used for XOR operations in fixed shift mode.
         *
         * @see FastBlurSimple#keyPart1
         */
        private final byte key;
        
        /**
         * Fixed shift value.
         * <br/>
         * The shift amount used in fixed shift mode.
         *
         * @see FastBlurSimple#shift
         */
        private final int shift;

        /**
         * Constructs a DecryptTask for a data segment.
         * <br/>
         * Initializes a task to decrypt a segment of a byte array using the 
         * specified key and shift parameters.
         *
         * @param data  the data array to process
         * @param start the start index of the segment
         * @param end   the end index of the segment
         * @param key   the key for XOR operations
         * @param shift the shift value for shift operations
         */
        DecryptTask(byte[] data, int start, int end, byte key, int shift) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.key = key;
            this.shift = shift;
        }

        /**
         * Computes the decryption task.
         * <br/>
         * Processes data segments smaller than the threshold directly, or splits 
         * larger segments into subtasks for parallel processing.
         *
         * <p>Algorithm:
         * For each byte in the segment:
         * 1. Apply fixed circular right shift if shift != 0
         * 2. XOR with the key
         * </p>
         *
         * <p>Note: Operations are performed in reverse order compared to encryption.
         * </p>
         *
         * @see RecursiveAction#compute()
         * @see FastBlurUtils#rotateRight(int, int)
         */
        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    if (shift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = FastBlurUtils.rotateRight(unsigned, shift);
                        data[i] = (byte) (shifted & 0xFF);
                    }
                    data[i] ^= key;
                }
            } else {
                // 分割任务
                int mid = (start + end) / 2;
                DecryptTask leftTask = new DecryptTask(data, start, mid, key, shift);
                DecryptTask rightTask = new DecryptTask(data, mid, end, key, shift);
                invokeAll(leftTask, rightTask);
            }
        }
    }
}