package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Adaptive Fast Blur Encryption Utility
 *
 * <p>A high-performance, lightweight encryption utility that automatically selects the optimal 
 * processing strategy based on data size. It uses dynamic bit shifting and XOR operations to 
 * achieve reversible data transformation. This implementation adaptively chooses between different 
 * optimized versions depending on the data size:</p>
 *
 * <ul>
 *   <li>Small Data (≤ 256 bytes): Uses ultra-fast lookup table optimized version</li>
 *   <li>Medium Data (256-4096 bytes): Uses vectorized optimized version</li>
 *   <li>Large Data (> 4096 bytes): Uses general optimized version</li>
 * </ul>
 *
 * <p>This class is designed for performance-critical applications where data obfuscation is 
 * required but cryptographic security is not a primary concern. The underlying algorithm 
 * combines dynamic bit shifts with XOR operations to achieve fast, reversible transformations.</p>
 *
 * <p>Example usage:
 * <pre>{@code
 * FastBlurAdaptive encryptor = new FastBlurAdaptive();
 * String original = "Hello World";
 * String encrypted = encryptor.encryptBase64(original.getBytes(StandardCharsets.UTF_8));
 * String decrypted = encryptor.decryptStr(encrypted);
 * assert original.equals(decrypted);
 * }</pre>
 * </p>
 *
 * @author HeHui
 * @since 1.0
 * @see FastBlurUltra Ultra-fast implementation for small data
 * @see FastBlurVectorized Vectorized implementation for medium data
 * @see FastBlurOptimized General optimized implementation for large data
 */
public class FastBlurAdaptive extends FastBlurBase {

    /**
     * Ultra-fast implementation instance for small data processing.
     * <p>Used when data size is ≤ 256 bytes for maximum performance.</p>
     */
    private final FastBlurUltra fastVersion;

    /**
     * Vectorized implementation instance for medium data processing.
     * <p>Used when data size is between 257-4096 bytes to leverage vectorization optimizations.</p>
     */
    private final FastBlurVectorized vectorizedVersion;

    /**
     * General optimized implementation instance for large data processing.
     * <p>Used when data size is > 4096 bytes for balanced performance and memory usage.</p>
     */
    private final FastBlurOptimized optimizedVersion;

    /**
     * Constructs a FastBlurAdaptive instance with UTF-8 character encoding.
     *
     * <p>This constructor initializes the adaptive blur engine with default parameters:
     * <ul>
     *   <li>Character encoding: UTF-8</li>
     *   <li>Default key: 0x5A7B9C1D3E8F0A2BL</li>
     *   <li>Dynamic shift mode enabled</li>
     *   <li>Parallel processing disabled</li>
     * </ul>
     * </p>
     *
     * <p>Example usage:
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive();
     * }</pre>
     * </p>
     *
     * @see #FastBlurAdaptive(Charset)
     */
    public FastBlurAdaptive() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * Constructs a FastBlurAdaptive instance with the specified character encoding.
     *
     * <p>This constructor initializes the adaptive blur engine with the given character encoding
     * and default key parameters. Dynamic shift mode is enabled with parallel processing disabled.</p>
     *
     * <p>Example usage:
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding Character encoding to use for string operations
     * @see #FastBlurAdaptive(Charset, long, byte)
     */
    public FastBlurAdaptive(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF), false);
    }

    /**
     * Constructs a FastBlurAdaptive instance with specified encoding, key, and key segment (dynamic shift mode).
     *
     * <p>This constructor initializes the adaptive blur engine with custom parameters in dynamic shift mode.
     * Parallel processing is disabled by default.</p>
     *
     * <p>Example usage:
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding   Character encoding to use for string operations
     * @param key        64-bit encryption key used for dynamic shifting calculations
     * @param keySegment Key segment value used for dynamic shift computation
     * @see #FastBlurAdaptive(Charset, long, int, boolean)
     */
    public FastBlurAdaptive(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, true);
    }

    /**
     * Constructs a FastBlurAdaptive instance with specified encoding, key, shift parameters, and dynamic shift option.
     *
     * <p>This constructor allows fine-grained control over the encryption parameters. Parallel processing
     * is disabled by default.</p>
     *
     * @param encoding     Character encoding to use for string operations
     * @param key          64-bit encryption key (for dynamic shift) or XOR key (for fixed shift)
     * @param shiftParam   Key segment value (for dynamic shift) or fixed shift value (0-7 for fixed shift)
     * @param dynamicShift Whether to enable dynamic shift mode
     * @see #FastBlurAdaptive(Charset, long, int, boolean, boolean)
     */
    public FastBlurAdaptive(Charset encoding, long key, int shiftParam, boolean dynamicShift) {
        this(encoding, key, shiftParam, dynamicShift, false);
    }

    /**
     * Constructs a FastBlurAdaptive instance with specified encoding, key, key segment, and parallel processing option (dynamic shift mode).
     *
     * <p>This constructor initializes the adaptive blur engine with custom parameters in dynamic shift mode
     * and enables or disables parallel processing based on the provided flag.</p>
     *
     * <p>Example usage:
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
     * }</pre>
     * </p>
     *
     * @param encoding           Character encoding to use for string operations
     * @param key                64-bit encryption key used for dynamic shifting calculations
     * @param keySegment         Key segment value used for dynamic shift computation
     * @param parallelProcessing Whether to enable parallel processing
     * @see #FastBlurAdaptive(Charset, long, int, boolean, boolean)
     */
    public FastBlurAdaptive(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        this(encoding, key, keySegment, true, parallelProcessing);
    }

    /**
     * Constructs a FastBlurAdaptive instance with full customization of all parameters.
     *
     * <p>This is the most flexible constructor that allows complete control over all encryption parameters,
     * including encoding, key, shift parameters, dynamic shift mode, and parallel processing options.</p>
     *
     * <p>The constructor initializes instances of all three specialized versions:
     * {@link FastBlurUltra}, {@link FastBlurVectorized}, and {@link FastBlurOptimized}
     * to enable adaptive processing based on data size.</p>
     *
     * @param encoding           Character encoding to use for string operations
     * @param key                64-bit encryption key (for dynamic shift) or XOR key (for fixed shift)
     * @param shiftParam         Key segment value (for dynamic shift) or fixed shift value (0-7 for fixed shift)
     * @param dynamicShift       Whether to enable dynamic shift mode
     * @param parallelProcessing Whether to enable parallel processing
     * @see FastBlurUltra
     * @see FastBlurVectorized
     * @see FastBlurOptimized
     */
    public FastBlurAdaptive(Charset encoding, long key, int shiftParam, boolean dynamicShift, boolean parallelProcessing) {
        super(encoding, parallelProcessing, dynamicShift,
              dynamicShift ? (byte) (key & 0xFF) : (byte) (key & 0xFF),
              dynamicShift ? (byte) ((key >> 8) & 0xFF) : (byte) 0,
              dynamicShift ? shiftParam & 0xFF : 0,
              dynamicShift ? 0 : shiftParam & 0x7);
              
        // 初始化各个版本的实例
        this.fastVersion = new FastBlurUltra(encoding, key, shiftParam, dynamicShift, parallelProcessing);
        this.vectorizedVersion = new FastBlurVectorized(encoding, key, shiftParam, dynamicShift, parallelProcessing);
        this.optimizedVersion = new FastBlurOptimized(encoding, key, shiftParam, dynamicShift, parallelProcessing);
    }

    /**
     * Encrypts a byte array using adaptive strategy selection based on data size.
     *
     * <p>This method automatically selects the optimal encryption strategy:
     * <ul>
     *   <li>Data ≤ 256 bytes: Uses {@link FastBlurUltra} for maximum performance</li>
     *   <li>Data 257-4096 bytes: Uses {@link FastBlurVectorized} for vectorization benefits</li>
     *   <li>Data > 4096 bytes: Uses {@link FastBlurOptimized} for balanced performance</li>
     * </ul>
     * </p>
     *
     * @param data Raw byte array to encrypt
     *
     * @return Encrypted byte array
     * @see FastBlurUltra#encrypt(byte[])
     * @see FastBlurVectorized#encrypt(byte[])
     * @see FastBlurOptimized#encrypt(byte[])
     */
    @Override
    public byte[] encrypt(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }

        // 根据数据大小选择最优处理策略
        if (data.length <= 256) {
            // 小数据使用极速版本
            return fastVersion.encrypt(data);
        } else if (data.length <= 4096) {
            // 中等数据使用向量化版本
            return vectorizedVersion.encrypt(data);
        } else {
            // 大数据使用优化版本
            return optimizedVersion.encrypt(data);
        }
    }

    /**
     * Decrypts a byte array using adaptive strategy selection based on data size.
     *
     * <p>This method automatically selects the optimal decryption strategy:
     * <ul>
     *   <li>Data ≤ 256 bytes: Uses {@link FastBlurUltra} for maximum performance</li>
     *   <li>Data 257-4096 bytes: Uses {@link FastBlurVectorized} for vectorization benefits</li>
     *   <li>Data > 4096 bytes: Uses {@link FastBlurOptimized} for balanced performance</li>
     * </ul>
     * </p>
     *
     * @param encryptedData Encrypted byte array to decrypt
     *
     * @return Decrypted (original) byte array
     * @see FastBlurUltra#decrypt(byte[])
     * @see FastBlurVectorized#decrypt(byte[])
     * @see FastBlurOptimized#decrypt(byte[])
     */
    @Override
    public byte[] decrypt(byte[] encryptedData) {
        if (encryptedData == null || encryptedData.length == 0) {
            return encryptedData;
        }

        // 根据数据大小选择最优处理策略
        if (encryptedData.length <= 256) {
            // 小数据使用极速版本
            return fastVersion.decrypt(encryptedData);
        } else if (encryptedData.length <= 4096) {
            // 中等数据使用向量化版本
            return vectorizedVersion.decrypt(encryptedData);
        } else {
            // 大数据使用优化版本
            return optimizedVersion.decrypt(encryptedData);
        }
    }

    /**
     * Performs zero-copy encryption on a ByteBuffer.
     *
     * <p>Directly operates on the ByteBuffer to avoid additional memory allocation.
     * This implementation falls back to the regular encryption method.</p>
     *
     * @param buffer ByteBuffer containing the raw data
     * @param offset Data offset within the buffer
     * @param length Length of data to process
     *
     * @return Execution result, true indicates success, false indicates failure
     * @see #encrypt(ByteBuffer, int, int)
     */
    @Override
    public boolean encryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规加密方法
        return encrypt(buffer, offset, length);
    }

    /**
     * Performs zero-copy decryption on a ByteBuffer.
     *
     * <p>Directly operates on the ByteBuffer to avoid additional memory allocation.
     * This implementation falls back to the regular decryption method.</p>
     *
     * @param buffer ByteBuffer containing the encrypted data
     * @param offset Data offset within the buffer
     * @param length Length of data to process
     *
     * @return Execution result, true indicates success, false indicates failure
     * @see #decrypt(ByteBuffer, int, int)
     */
    @Override
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规解密方法
        return decrypt(buffer, offset, length);
    }
}