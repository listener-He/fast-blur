package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

/**
 * Simple lightweight obfuscation algorithm (vectorized version).
 * <br/>
 * High-performance reversible lightweight encryption tool (supports fixed shift and
 * dynamic shift enhanced obfuscation, security not guaranteed). Core: dynamic shift +
 * XOR bitwise operations, extremely fast, reversible, obfuscation superior to fixed shift.
 *
 * <p>This class provides a simple data obfuscation mechanism that implements
 * reversible data transformation through dynamic shift and XOR operations.
 * Optimized with vectorized processing concepts, suitable for lightweight data
 * protection scenarios requiring extreme performance.</p>
 *
 * <p>Vectorized optimizations:
 * 1. Batch processing data to reduce loop overhead
 * 2. Reduce conditional branches to improve branch prediction accuracy
 * 3. Optimize memory access patterns to improve cache hit rate
 * 4. Use loop unrolling to reduce CPU pipeline stalls
 * 5. Support both fixed shift and dynamic shift modes
 * </p>
 *
 * <p>Design Philosophy:
 * The vectorized approach focuses on processing multiple data elements in parallel
 * to maximize throughput. This implementation uses techniques like batch processing
 * and loop unrolling to reduce overhead and improve performance.
 * </p>
 *
 * <p>Usage example:
 * <pre>{@code
 * FastBlurVectorized encryptor = new FastBlurVectorized();
 * String original = "Hello World";
 * String encrypted = encryptor.encryptBase64(original.getBytes(StandardCharsets.UTF_8));
 * String decrypted = encryptor.decryptStr(encrypted);
 * assert original.equals(decrypted);
 * }</pre>
 * </p>
 *
 * @author HeHui
 * @see FastBlurBase
 * @see FastBlurStrategy#VECTOR
 * @since 1.0
 */
public class FastBlurVectorized extends FastBlurBase {

    /**
     * Default constructor using UTF-8 character set encoding.
     * <br/>
     * Initializes a FastBlurVectorized instance with UTF-8 encoding and default
     * configuration values. Dynamic shifting is enabled and parallel processing
     * is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurVectorized blur = new FastBlurVectorized();
     * }</pre>
     * </p>
     *
     * @see StandardCharsets#UTF_8
     */
    public FastBlurVectorized() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * Constructor initializing a FastBlurVectorized instance with the specified encoding.
     * <br/>
     * Initializes a FastBlurVectorized instance with the given character encoding and
     * default key and shift values. Dynamic shifting is enabled and parallel processing
     * is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurVectorized blur = new FastBlurVectorized(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding character encoding method
     *
     * @see Charset
     */
    public FastBlurVectorized(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF), false);
    }

    /**
     * Constructor initializing a FastBlurVectorized instance with the specified encoding,
     * key, and key segment (dynamic shift mode).
     * <br/>
     * Initializes a FastBlurVectorized instance in dynamic shift mode with the given
     * parameters. Parallel processing is disabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurVectorized blur = new FastBlurVectorized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding   character encoding method
     * @param key        64-bit key
     * @param keySegment key segment value for dynamic shift calculation
     *
     * @see Charset
     */
    public FastBlurVectorized(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, false);
    }

    /**
     * Constructor initializing a FastBlurVectorized instance with the specified encoding,
     * key, key segment, and parallel processing option (dynamic shift mode).
     * <br/>
     * Initializes a FastBlurVectorized instance in dynamic shift mode with the given
     * parameters. Parallel processing can be enabled.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurVectorized blur = new FastBlurVectorized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
     * }</pre>
     * </p>
     *
     * @param encoding           character encoding method
     * @param key                64-bit key
     * @param keySegment         key segment value for dynamic shift calculation
     * @param parallelProcessing whether to enable parallel processing
     *
     * @see Charset
     * @see #parallelProcessing
     */
    public FastBlurVectorized(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        this(encoding, key, keySegment, true, parallelProcessing);
    }

    /**
     * Constructor initializing a FastBlurVectorized instance with the specified encoding,
     * key, shift parameter, dynamic shift option, and parallel processing option.
     * <br/>
     * Fully configurable constructor for FastBlurVectorized instances.
     *
     * @param encoding           character encoding method
     * @param key                64-bit key (dynamic shift) or key for XOR operations (fixed shift)
     * @param shiftParam         key segment value (dynamic shift) or fixed shift value (fixed shift, 0-7)
     * @param dynamicShift       whether to enable dynamic shift
     * @param parallelProcessing whether to enable parallel processing
     *
     * @see Charset
     * @see #dynamicShift
     * @see #parallelProcessing
     */
    public FastBlurVectorized(Charset encoding, long key, int shiftParam, boolean dynamicShift, boolean parallelProcessing) {
        super(encoding, parallelProcessing, dynamicShift,
            dynamicShift ? (byte) (key & 0xFF) : (byte) (key & 0xFF),
            dynamicShift ? (byte) ((key >> 8) & 0xFF) : (byte) 0,
            dynamicShift ? shiftParam & 0xFF : 0,
            dynamicShift ? 0 : shiftParam & 0x7);
    }

    /**
     * Constructor initializing a FastBlurVectorized instance with the specified encoding,
     * key, shift parameter, dynamic shift option, and custom ForkJoinPool.
     * <br/>
     * Fully configurable constructor for FastBlurVectorized instances with custom ForkJoinPool.
     *
     * @param encoding     character encoding method
     * @param key          64-bit key (dynamic shift) or key for XOR operations (fixed shift)
     * @param shiftParam   key segment value (dynamic shift) or fixed shift value (fixed shift, 0-7)
     * @param dynamicShift whether to enable dynamic shift
     * @param pool         custom ForkJoinPool for parallel processing
     *
     * @see Charset
     * @see #dynamicShift
     */
    public FastBlurVectorized(Charset encoding, long key, int shiftParam, boolean dynamicShift, java.util.concurrent.ForkJoinPool pool) {
        super(encoding, true, dynamicShift,
            dynamicShift ? (byte) (key & 0xFF) : (byte) (key & 0xFF),
            dynamicShift ? (byte) ((key >> 8) & 0xFF) : (byte) 0,
            dynamicShift ? shiftParam & 0xFF : 0,
            dynamicShift ? 0 : shiftParam & 0x7,
            pool);
    }

    /**
     * Vectorized encryption of byte array (supports fixed shift and dynamic shift enhanced obfuscation).
     * <br/>
     * Improves performance through batch processing and reduced branching.
     *
     * <p>Algorithm Details:
     * In dynamic shift mode:
     * 1. XOR data with first key fragment ({@link #keyPart1})
     * 2. Apply dynamic circular left shift based on byte position
     * 3. XOR result with second key fragment ({@link #keyPart2})
     * <p>
     * In fixed shift mode:
     * 1. XOR data with the key ({@link #keyPart1})
     * 2. Apply fixed circular left shift ({@link #shift})
     * </p>
     *
     * <p>Vectorization Techniques:
     * - Processes 8 bytes at a time in the main loop
     * - Pre-calculates shift values for all bytes in a batch
     * - Reduces branching by handling fixed shift mode separately
     * - Operates directly on input array to avoid memory copy overhead
     * </p>
     *
     * <p>Performance Optimizations:
     * - For large data (≥8KB) with {@link #parallelProcessing} enabled, uses parallel processing
     * - Uses local variables to cache frequently accessed fields
     * - Handles remaining bytes separately after main loop
     * </p>
     *
     * @param data the original byte array
     *
     * @return the encrypted byte array (same array as input)
     *
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
        if (parallelProcessing && data.length >= 8192) {
            return encryptParallel(data);
        }

        if (dynamicShift) {
            // 动态位移模式
            final int len = data.length;
            final byte kp1 = keyPart1;
            final byte kp2 = keyPart2;
            final int mask = shiftMask;

            int i = 0;

            // 主循环：每次处理8个字节
            for (; i <= len - 8; i += 8) {
                // 批量计算位移值
                final int s0 = FastBlurUtils.getDynamicShift(i, mask);
                final int s1 = FastBlurUtils.getDynamicShift(i + 1, mask);
                final int s2 = FastBlurUtils.getDynamicShift(i + 2, mask);
                final int s3 = FastBlurUtils.getDynamicShift(i + 3, mask);
                final int s4 = FastBlurUtils.getDynamicShift(i + 4, mask);
                final int s5 = FastBlurUtils.getDynamicShift(i + 5, mask);
                final int s6 = FastBlurUtils.getDynamicShift(i + 6, mask);
                final int s7 = FastBlurUtils.getDynamicShift(i + 7, mask);

                // 批量处理加密操作
                data[i] ^= kp1;
                if (s0 != 0) {
                    final int u = data[i] & 0xFF;
                    data[i] = (byte) (FastBlurUtils.rotateLeft(u, s0) & 0xFF);
                }
                data[i] ^= kp2;

                data[i + 1] ^= kp1;
                if (s1 != 0) {
                    final int u = data[i + 1] & 0xFF;
                    data[i + 1] = (byte) (FastBlurUtils.rotateLeft(u, s1) & 0xFF);
                }
                data[i + 1] ^= kp2;

                data[i + 2] ^= kp1;
                if (s2 != 0) {
                    final int u = data[i + 2] & 0xFF;
                    data[i + 2] = (byte) (FastBlurUtils.rotateLeft(u, s2) & 0xFF);
                }
                data[i + 2] ^= kp2;

                data[i + 3] ^= kp1;
                if (s3 != 0) {
                    final int u = data[i + 3] & 0xFF;
                    data[i + 3] = (byte) (FastBlurUtils.rotateLeft(u, s3) & 0xFF);
                }
                data[i + 3] ^= kp2;

                data[i + 4] ^= kp1;
                if (s4 != 0) {
                    final int u = data[i + 4] & 0xFF;
                    data[i + 4] = (byte) (FastBlurUtils.rotateLeft(u, s4) & 0xFF);
                }
                data[i + 4] ^= kp2;

                data[i + 5] ^= kp1;
                if (s5 != 0) {
                    final int u = data[i + 5] & 0xFF;
                    data[i + 5] = (byte) (FastBlurUtils.rotateLeft(u, s5) & 0xFF);
                }
                data[i + 5] ^= kp2;

                data[i + 6] ^= kp1;
                if (s6 != 0) {
                    final int u = data[i + 6] & 0xFF;
                    data[i + 6] = (byte) (FastBlurUtils.rotateLeft(u, s6) & 0xFF);
                }
                data[i + 6] ^= kp2;

                data[i + 7] ^= kp1;
                if (s7 != 0) {
                    final int u = data[i + 7] & 0xFF;
                    data[i + 7] = (byte) (FastBlurUtils.rotateLeft(u, s7) & 0xFF);
                }
                data[i + 7] ^= kp2;
            }

            // 处理剩余不足8个字节的数据
            for (; i < len; i++) {
                final int shift = FastBlurUtils.getDynamicShift(i, mask);
                data[i] ^= kp1;
                if (shift != 0) {
                    final int u = data[i] & 0xFF;
                    data[i] = (byte) (FastBlurUtils.rotateLeft(u, shift) & 0xFF);
                }
                data[i] ^= kp2;
            }
        } else {
            // 固定位移模式
            final int len = data.length;
            final byte kp1 = keyPart1;
            final int sh = shift;

            int i = 0;

            // 主循环：每次处理8个字节
            for (; i <= len - 8; i += 8) {
                // 批量处理加密操作
                data[i] ^= kp1;
                if (sh != 0) {
                    final int u = data[i] & 0xFF;
                    data[i] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }

                data[i + 1] ^= kp1;
                if (sh != 0) {
                    final int u = data[i + 1] & 0xFF;
                    data[i + 1] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }

                data[i + 2] ^= kp1;
                if (sh != 0) {
                    final int u = data[i + 2] & 0xFF;
                    data[i + 2] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }

                data[i + 3] ^= kp1;
                if (sh != 0) {
                    final int u = data[i + 3] & 0xFF;
                    data[i + 3] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }

                data[i + 4] ^= kp1;
                if (sh != 0) {
                    final int u = data[i + 4] & 0xFF;
                    data[i + 4] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }

                data[i + 5] ^= kp1;
                if (sh != 0) {
                    final int u = data[i + 5] & 0xFF;
                    data[i + 5] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }

                data[i + 6] ^= kp1;
                if (sh != 0) {
                    final int u = data[i + 6] & 0xFF;
                    data[i + 6] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }

                data[i + 7] ^= kp1;
                if (sh != 0) {
                    final int u = data[i + 7] & 0xFF;
                    data[i + 7] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }
            }

            // 处理剩余不足8个字节的数据
            for (; i < len; i++) {
                data[i] ^= kp1;
                if (sh != 0) {
                    final int u = data[i] & 0xFF;
                    data[i] = (byte) (FastBlurUtils.rotateLeft(u, sh) & 0xFF);
                }
            }
        }

        return data;
    }

    /**
     * Vectorized decryption of byte array.
     * <br/>
     * Improves performance through batch processing and reduced branching.
     *
     * <p>Algorithm Details (Inverse of encryption):
     * In dynamic shift mode:
     * 1. XOR data with second key fragment ({@link #keyPart2})
     * 2. Apply dynamic circular right shift based on byte position
     * 3. XOR result with first key fragment ({@link #keyPart1})
     * <p>
     * In fixed shift mode:
     * 1. Apply fixed circular right shift ({@link #shift})
     * 2. XOR data with the key ({@link #keyPart1})
     * </p>
     *
     * <p>Vectorization Techniques:
     * - Processes 8 bytes at a time in the main loop
     * - Pre-calculates shift values for all bytes in a batch
     * - Reduces branching by handling fixed shift mode separately
     * - Operates directly on input array to avoid memory copy overhead
     * </p>
     *
     * <p>Performance Optimizations:
     * - For large data (≥8KB) with {@link #parallelProcessing} enabled, uses parallel processing
     * - Uses local variables to cache frequently accessed fields
     * - Handles remaining bytes separately after main loop
     * - Operations executed in reverse order compared to encryption
     * </p>
     *
     * @param encryptedData the encrypted byte array
     *
     * @return the original byte array (same array as input)
     *
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
        if (parallelProcessing && encryptedData.length >= 8192) {
            return decryptParallel(encryptedData);
        }

        final int len = encryptedData.length;
        final byte kp1 = keyPart1;
        final byte kp2 = keyPart2;
        final int mask = shiftMask;

        int i = 0;

        // 主循环：每次处理8个字节
        for (; i <= len - 8; i += 8) {
            // 批量计算位移值
            final int s0 = FastBlurUtils.getDynamicShift(i, mask);
            final int s1 = FastBlurUtils.getDynamicShift(i + 1, mask);
            final int s2 = FastBlurUtils.getDynamicShift(i + 2, mask);
            final int s3 = FastBlurUtils.getDynamicShift(i + 3, mask);
            final int s4 = FastBlurUtils.getDynamicShift(i + 4, mask);
            final int s5 = FastBlurUtils.getDynamicShift(i + 5, mask);
            final int s6 = FastBlurUtils.getDynamicShift(i + 6, mask);
            final int s7 = FastBlurUtils.getDynamicShift(i + 7, mask);

            // 批量处理解密操作（逆序执行加密的逆操作）
            encryptedData[i] ^= kp2;
            if (s0 != 0) {
                final int u = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (FastBlurUtils.rotateRight(u, s0) & 0xFF);
            }
            encryptedData[i] ^= kp1;

            encryptedData[i + 1] ^= kp2;
            if (s1 != 0) {
                final int u = encryptedData[i + 1] & 0xFF;
                encryptedData[i + 1] = (byte) (FastBlurUtils.rotateRight(u, s1) & 0xFF);
            }
            encryptedData[i + 1] ^= kp1;

            encryptedData[i + 2] ^= kp2;
            if (s2 != 0) {
                final int u = encryptedData[i + 2] & 0xFF;
                encryptedData[i + 2] = (byte) (FastBlurUtils.rotateRight(u, s2) & 0xFF);
            }
            encryptedData[i + 2] ^= kp1;

            encryptedData[i + 3] ^= kp2;
            if (s3 != 0) {
                final int u = encryptedData[i + 3] & 0xFF;
                encryptedData[i + 3] = (byte) (FastBlurUtils.rotateRight(u, s3) & 0xFF);
            }
            encryptedData[i + 3] ^= kp1;

            encryptedData[i + 4] ^= kp2;
            if (s4 != 0) {
                final int u = encryptedData[i + 4] & 0xFF;
                encryptedData[i + 4] = (byte) (FastBlurUtils.rotateRight(u, s4) & 0xFF);
            }
            encryptedData[i + 4] ^= kp1;

            encryptedData[i + 5] ^= kp2;
            if (s5 != 0) {
                final int u = encryptedData[i + 5] & 0xFF;
                encryptedData[i + 5] = (byte) (FastBlurUtils.rotateRight(u, s5) & 0xFF);
            }
            encryptedData[i + 5] ^= kp1;

            encryptedData[i + 6] ^= kp2;
            if (s6 != 0) {
                final int u = encryptedData[i + 6] & 0xFF;
                encryptedData[i + 6] = (byte) (FastBlurUtils.rotateRight(u, s6) & 0xFF);
            }
            encryptedData[i + 6] ^= kp1;

            encryptedData[i + 7] ^= kp2;
            if (s7 != 0) {
                final int u = encryptedData[i + 7] & 0xFF;
                encryptedData[i + 7] = (byte) (FastBlurUtils.rotateRight(u, s7) & 0xFF);
            }
            encryptedData[i + 7] ^= kp1;
        }

        // 处理剩余不足8个字节的数据
        for (; i < len; i++) {
            final int shift = FastBlurUtils.getDynamicShift(i, mask);
            encryptedData[i] ^= kp2;
            if (shift != 0) {
                final int u = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (FastBlurUtils.rotateRight(u, shift) & 0xFF);
            }
            encryptedData[i] ^= kp1;
        }

        return encryptedData;
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
     *
     * @return execution result, true for success, false for failure
     *
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
     *
     * @return execution result, true for success, false for failure
     *
     * @see #decrypt(ByteBuffer, int, int)
     * @see ByteBuffer#isDirect()
     */
    @Override
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规解密方法
        return decrypt(buffer, offset, length);
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
     * - Parallel processing is triggered for data ≥8KB in {@link #encrypt(byte[])}
     * - Task splitting threshold is 4KB in {@link EncryptTask}
     * </p>
     *
     * @param data the original byte array
     *
     * @return the encrypted byte array
     *
     * @see #encrypt(byte[])
     * @see EncryptTask
     * @see ForkJoinPool#commonPool()
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
     *
     * @return the encrypted byte array
     *
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
        pool.invoke(new EncryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask));

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
     * - Parallel processing is triggered for data ≥8KB in {@link #decrypt(byte[])}
     * - Task splitting threshold is 4KB in {@link DecryptTask}
     * </p>
     *
     * @param encryptedData the encrypted byte array
     *
     * @return the original byte array
     *
     * @see #decrypt(byte[])
     * @see DecryptTask
     * @see ForkJoinPool#commonPool()
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
     * @param pool          the ForkJoinPool to use for parallel processing
     *
     * @return the original byte array
     *
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
        pool.invoke(new DecryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask));

        return dataCopy;
    }

    /**
     * Encryption task for parallel processing.
     * <br/>
     * A RecursiveAction that handles encryption of a data segment in parallel.
     * Processes data segments smaller than the threshold directly, and splits
     * larger segments into subtasks.
     *
     * <p>Parallel Processing Strategy:
     * - Threshold: 4KB data segments
     * - Work splitting: Divides large segments in half recursively
     * - Processing: Direct encryption of small segments using vectorized approach
     * </p>
     *
     * @see RecursiveAction
     * @see #encryptParallel(byte[])
     */
    private static class EncryptTask extends RecursiveAction {
        /**
         * Task threshold: 4KB.
         * <br/>
         * Data segments smaller than this threshold are processed directly.
         * Larger segments are split into subtasks.
         */
        private static final int THRESHOLD = 4096; // 任务阈值：4KB

        private static final long serialVersionUID = -1134508474606636622L;

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
         * @see FastBlurVectorized#keyPart1
         */
        private final byte keyPart1;

        /**
         * Second key fragment for XOR operations.
         * <br/>
         * The second part of a split-key approach. In dynamic shift mode,
         * this is applied after the shift operation, providing a form of double
         * encryption for each byte.
         *
         * @see FastBlurVectorized#keyPart2
         */
        private final byte keyPart2;

        /**
         * Mask used for shift calculation.
         * <br/>
         * In dynamic shift mode, this mask is used in conjunction with the byte
         * position to calculate the specific shift amount for each byte.
         *
         * @see FastBlurVectorized#shiftMask
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
         * Processes data segments smaller than the threshold directly using a
         * vectorized approach, or splits larger segments into subtasks for parallel processing.
         *
         * <p>Vectorized Algorithm:
         * For each group of 8 bytes in the segment:
         * 1. Pre-calculate shift values for all 8 bytes
         * 2. For each byte:
         * a. XOR with first key fragment
         * b. Apply dynamic circular left shift if shift != 0
         * c. XOR with second key fragment
         * </p>
         *
         * @see RecursiveAction#compute()
         * @see FastBlurUtils#rotateLeft(int, int)
         * @see FastBlurUtils#getDynamicShift(int, int)
         */
        @Override
        protected void compute() {
            final byte kp1 = keyPart1;
            final byte kp2 = keyPart2;
            final int mask = shiftMask;

            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                int i = start;

                // 主循环：每次处理8个字节
                for (; i <= end - 8; i += 8) {
                    // 批量计算位移值
                    final int s0 = FastBlurUtils.getDynamicShift(i, mask);
                    final int s1 = FastBlurUtils.getDynamicShift(i + 1, mask);
                    final int s2 = FastBlurUtils.getDynamicShift(i + 2, mask);
                    final int s3 = FastBlurUtils.getDynamicShift(i + 3, mask);
                    final int s4 = FastBlurUtils.getDynamicShift(i + 4, mask);
                    final int s5 = FastBlurUtils.getDynamicShift(i + 5, mask);
                    final int s6 = FastBlurUtils.getDynamicShift(i + 6, mask);
                    final int s7 = FastBlurUtils.getDynamicShift(i + 7, mask);

                    // 批量处理加密操作
                    data[i] ^= kp1;
                    if (s0 != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (FastBlurUtils.rotateLeft(u, s0) & 0xFF);
                    }
                    data[i] ^= kp2;

                    data[i + 1] ^= kp1;
                    if (s1 != 0) {
                        final int u = data[i + 1] & 0xFF;
                        data[i + 1] = (byte) (FastBlurUtils.rotateLeft(u, s1) & 0xFF);
                    }
                    data[i + 1] ^= kp2;

                    data[i + 2] ^= kp1;
                    if (s2 != 0) {
                        final int u = data[i + 2] & 0xFF;
                        data[i + 2] = (byte) (FastBlurUtils.rotateLeft(u, s2) & 0xFF);
                    }
                    data[i + 2] ^= kp2;

                    data[i + 3] ^= kp1;
                    if (s3 != 0) {
                        final int u = data[i + 3] & 0xFF;
                        data[i + 3] = (byte) (FastBlurUtils.rotateLeft(u, s3) & 0xFF);
                    }
                    data[i + 3] ^= kp2;

                    data[i + 4] ^= kp1;
                    if (s4 != 0) {
                        final int u = data[i + 4] & 0xFF;
                        data[i + 4] = (byte) (FastBlurUtils.rotateLeft(u, s4) & 0xFF);
                    }
                    data[i + 4] ^= kp2;

                    data[i + 5] ^= kp1;
                    if (s5 != 0) {
                        final int u = data[i + 5] & 0xFF;
                        data[i + 5] = (byte) (FastBlurUtils.rotateLeft(u, s5) & 0xFF);
                    }
                    data[i + 5] ^= kp2;

                    data[i + 6] ^= kp1;
                    if (s6 != 0) {
                        final int u = data[i + 6] & 0xFF;
                        data[i + 6] = (byte) (FastBlurUtils.rotateLeft(u, s6) & 0xFF);
                    }
                    data[i + 6] ^= kp2;

                    data[i + 7] ^= kp1;
                    if (s7 != 0) {
                        final int u = data[i + 7] & 0xFF;
                        data[i + 7] = (byte) (FastBlurUtils.rotateLeft(u, s7) & 0xFF);
                    }
                    data[i + 7] ^= kp2;
                }

                // 处理剩余不足8个字节的数据
                for (; i < end; i++) {
                    final int shift = FastBlurUtils.getDynamicShift(i, mask);
                    data[i] ^= kp1;
                    if (shift != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (FastBlurUtils.rotateLeft(u, shift) & 0xFF);
                    }
                    data[i] ^= kp2;
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
     * - Threshold: 4KB data segments
     * - Work splitting: Divides large segments in half recursively
     * - Processing: Direct decryption of small segments using vectorized approach
     * </p>
     *
     * @see RecursiveAction
     * @see #decryptParallel(byte[])
     */
    private static class DecryptTask extends RecursiveAction {
        /**
         * Task threshold: 4KB.
         * <br/>
         * Data segments smaller than this threshold are processed directly.
         * Larger segments are split into subtasks.
         */
        private static final int THRESHOLD = 4096; // 任务阈值：4KB

        private static final long serialVersionUID = 6527346346469821233L;

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
         * @see FastBlurVectorized#keyPart1
         */
        private final byte keyPart1;

        /**
         * Second key fragment for XOR operations.
         * <br/>
         * The second part of a split-key approach. In dynamic shift mode,
         * this is applied before the shift operation during decryption.
         *
         * @see FastBlurVectorized#keyPart2
         */
        private final byte keyPart2;

        /**
         * Mask used for shift calculation.
         * <br/>
         * In dynamic shift mode, this mask is used in conjunction with the byte
         * position to calculate the specific shift amount for each byte.
         *
         * @see FastBlurVectorized#shiftMask
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
         * Processes data segments smaller than the threshold directly using a
         * vectorized approach, or splits larger segments into subtasks for parallel processing.
         *
         * <p>Vectorized Algorithm (Inverse of encryption):
         * For each group of 8 bytes in the segment:
         * 1. Pre-calculate shift values for all 8 bytes
         * 2. For each byte:
         * a. XOR with second key fragment
         * b. Apply dynamic circular right shift if shift != 0
         * c. XOR with first key fragment
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
            final byte kp1 = keyPart1;
            final byte kp2 = keyPart2;
            final int mask = shiftMask;

            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                int i = start;

                // 主循环：每次处理8个字节
                for (; i <= end - 8; i += 8) {
                    // 批量计算位移值
                    final int s0 = FastBlurUtils.getDynamicShift(i, mask);
                    final int s1 = FastBlurUtils.getDynamicShift(i + 1, mask);
                    final int s2 = FastBlurUtils.getDynamicShift(i + 2, mask);
                    final int s3 = FastBlurUtils.getDynamicShift(i + 3, mask);
                    final int s4 = FastBlurUtils.getDynamicShift(i + 4, mask);
                    final int s5 = FastBlurUtils.getDynamicShift(i + 5, mask);
                    final int s6 = FastBlurUtils.getDynamicShift(i + 6, mask);
                    final int s7 = FastBlurUtils.getDynamicShift(i + 7, mask);

                    // 批量处理解密操作（逆序执行加密的逆操作）
                    data[i] ^= kp2;
                    if (s0 != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (FastBlurUtils.rotateRight(u, s0) & 0xFF);
                    }
                    data[i] ^= kp1;

                    data[i + 1] ^= kp2;
                    if (s1 != 0) {
                        final int u = data[i + 1] & 0xFF;
                        data[i + 1] = (byte) (FastBlurUtils.rotateRight(u, s1) & 0xFF);
                    }
                    data[i + 1] ^= kp1;

                    data[i + 2] ^= kp2;
                    if (s2 != 0) {
                        final int u = data[i + 2] & 0xFF;
                        data[i + 2] = (byte) (FastBlurUtils.rotateRight(u, s2) & 0xFF);
                    }
                    data[i + 2] ^= kp1;

                    data[i + 3] ^= kp2;
                    if (s3 != 0) {
                        final int u = data[i + 3] & 0xFF;
                        data[i + 3] = (byte) (FastBlurUtils.rotateRight(u, s3) & 0xFF);
                    }
                    data[i + 3] ^= kp1;

                    data[i + 4] ^= kp2;
                    if (s4 != 0) {
                        final int u = data[i + 4] & 0xFF;
                        data[i + 4] = (byte) (FastBlurUtils.rotateRight(u, s4) & 0xFF);
                    }
                    data[i + 4] ^= kp1;

                    data[i + 5] ^= kp2;
                    if (s5 != 0) {
                        final int u = data[i + 5] & 0xFF;
                        data[i + 5] = (byte) (FastBlurUtils.rotateRight(u, s5) & 0xFF);
                    }
                    data[i + 5] ^= kp1;

                    data[i + 6] ^= kp2;
                    if (s6 != 0) {
                        final int u = data[i + 6] & 0xFF;
                        data[i + 6] = (byte) (FastBlurUtils.rotateRight(u, s6) & 0xFF);
                    }
                    data[i + 6] ^= kp1;

                    data[i + 7] ^= kp2;
                    if (s7 != 0) {
                        final int u = data[i + 7] & 0xFF;
                        data[i + 7] = (byte) (FastBlurUtils.rotateRight(u, s7) & 0xFF);
                    }
                    data[i + 7] ^= kp1;
                }

                // 处理剩余不足8个字节的数据
                for (; i < end; i++) {
                    final int shift = FastBlurUtils.getDynamicShift(i, mask);
                    data[i] ^= kp2;
                    if (shift != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (FastBlurUtils.rotateRight(u, shift) & 0xFF);
                    }
                    data[i] ^= kp1;
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
