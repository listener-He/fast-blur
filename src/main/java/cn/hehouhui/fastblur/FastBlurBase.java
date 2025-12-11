package cn.hehouhui.fastblur;


import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Abstract base class for FastBlur algorithms.
 * <br/>
 * High-performance reversible lightweight encryption tool (dynamic shift enhanced obfuscation, 
 * security not guaranteed). Core: shift + XOR bitwise operations, reversible, obfuscation 
 * superior to fixed shift.
 *
 * <p>This class provides a simple data obfuscation mechanism base class that implements 
 * reversible data transformation through shift and XOR operations. Subclasses can implement 
 * different optimization strategies to meet specific performance requirements.</p>
 *
 * <p>Design Philosophy:
 * The FastBlur algorithm is designed as a lightweight data obfuscation technique rather 
 * than a secure encryption method. It combines bitwise operations (XOR and rotation) 
 * with dynamic shifting to provide reasonable obfuscation while maintaining high performance.
 * </p>
 *
 * <p>Usage example:
 * <pre>{@code
 * FastBlurBase encryptor = FastBlurBase.builder()
 *     .withEncoding(StandardCharsets.UTF_8)
 *     .withStrategy(FastBlurStrategy.MEMORY_FIRST)
 *     .build();
 * String original = "Hello World";
 * String encrypted = encryptor.encryptBase64(original.getBytes(StandardCharsets.UTF_8));
 * String decrypted = encryptor.decryptStr(encrypted);
 * assert original.equals(decrypted);
 * }</pre>
 * </p>
 *
 * @author HeHui
 * @since 1.0
 * @see FastBlurStrategy
 * @see FastBlurBuilder
 */
public abstract class FastBlurBase {

    /**
     * Character encoding method, defaults to UTF-8.
     * <br/>
     * This field determines how strings are converted to and from byte arrays during 
     * encryption and decryption operations. UTF-8 is used as the default encoding 
     * for broad compatibility with international character sets.
     *
     * @see StandardCharsets#UTF_8
     */
    protected final Charset encoding;

    /**
     * Whether parallel processing is enabled.
     * <br/>
     * When enabled, large data sets will be processed using parallel computing 
     * techniques to improve performance on multi-core systems. This flag controls 
     * whether the implementation should attempt to leverage multiple CPU cores.
     *
     * @see #encryptParallel(byte[])
     * @see #decryptParallel(byte[])
     */
    protected final boolean parallelProcessing;
    
    /**
     * Whether dynamic shifting is enabled.
     * <br/>
     * Dynamic shifting varies the bit shift amount based on the position of each 
     * byte in the data array. This provides better obfuscation compared to fixed 
     * shifting, as identical bytes at different positions will be transformed differently.
     *
     * @see FastBlurUtils#getDynamicShift(int, int)
     */
    protected final boolean dynamicShift;
    
    /**
     * Precomputed key fragment 1 (used for XOR operations).
     * <br/>
     * This is the first part of a split-key approach where the key is divided 
     * into multiple parts that are applied at different stages of the encryption 
     * process. In dynamic shift mode, this is applied before the shift operation.
     */
    protected final byte keyPart1;
    
    /**
     * Precomputed key fragment 2 (used for XOR operations).
     * <br/>
     * This is the second part of a split-key approach. In dynamic shift mode, 
     * this is applied after the shift operation, providing a form of double 
     * encryption for each byte.
     */
    protected final byte keyPart2;
    
    /**
     * Mask used for shift calculation.
     * <br/>
     * In dynamic shift mode, this mask is used in conjunction with the byte 
     * position to calculate the specific shift amount for each byte. This 
     * contributes to the dynamic nature of the algorithm.
     *
     * @see FastBlurUtils#getDynamicShift(int, int)
     */
    protected final int shiftMask;
    
    /**
     * Fixed shift value.
     * <br/>
     * In fixed shift mode, this value determines how many bit positions each 
     * byte will be shifted during encryption. The value is constrained to 
     * the range 0-7 as only 8-bit values are being processed.
     */
    protected final int shift;

    /**
     * Constructor using default UTF-8 encoding.
     * <br/>
     * Initializes a FastBlurBase instance with UTF-8 character encoding and 
     * default configuration values. Parallel processing is disabled, dynamic 
     * shifting is enabled, and default key fragments are used.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurBase encryptor = new FastBlurOptimized(); // Uses this constructor internally
     * }</pre>
     * </p>
     *
     * @see StandardCharsets#UTF_8
     */
    protected FastBlurBase() {
        this(StandardCharsets.UTF_8, false, true, (byte) 0, (byte) 0, 0, 0);
    }

    /**
     * Constructor with specified encoding.
     * <br/>
     * Initializes a FastBlurBase instance with the specified character encoding 
     * and default configuration values. Parallel processing is disabled, dynamic 
     * shifting is enabled, and default key fragments are used.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurBase encryptor = new FastBlurOptimized(StandardCharsets.UTF_16);
     * }</pre>
     * </p>
     *
     * @param encoding character encoding method to use
     * @see Charset
     */
    protected FastBlurBase(Charset encoding) {
        this(encoding, false, true, (byte) 0, (byte) 0, 0, 0);
    }

    /**
     * Constructor with specified encoding and parallel processing option.
     * <br/>
     * Initializes a FastBlurBase instance with the specified character encoding 
     * and parallel processing option. Dynamic shifting is enabled, and default 
     * key fragments are used.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurBase encryptor = new FastBlurOptimized(StandardCharsets.UTF_8, true);
     * }</pre>
     * </p>
     *
     * @param encoding character encoding method to use
     * @param parallelProcessing whether to enable parallel processing
     * @see Charset
     * @see #parallelProcessing
     */
    protected FastBlurBase(Charset encoding, boolean parallelProcessing) {
        this(encoding, parallelProcessing, true, (byte) 0, (byte) 0, 0, 0);
    }
    
    /**
     * Constructor with complete parameter list.
     * <br/>
     * Fully configurable constructor allowing specification of all FastBlurBase 
     * parameters. This is typically called by subclass constructors to initialize 
     * all fields.
     *
     * @param encoding character encoding method to use
     * @param parallelProcessing whether to enable parallel processing
     * @param dynamicShift whether to enable dynamic shifting
     * @param keyPart1 first key fragment for XOR operations
     * @param keyPart2 second key fragment for XOR operations
     * @param shiftMask mask used for shift calculation in dynamic mode
     * @param shift fixed shift value used in static mode
     * @see Charset
     */
    protected FastBlurBase(Charset encoding, boolean parallelProcessing, boolean dynamicShift, 
                          byte keyPart1, byte keyPart2, int shiftMask, int shift) {
        this.encoding = encoding;
        this.parallelProcessing = parallelProcessing;
        this.dynamicShift = dynamicShift;
        this.keyPart1 = keyPart1;
        this.keyPart2 = keyPart2;
        this.shiftMask = shiftMask;
        this.shift = shift;
    }

    /**
     * Encrypts a byte array.
     * <br/>
     * This abstract method must be implemented by subclasses to provide 
     * specific encryption logic. The method transforms the input data using 
     * the configured algorithm parameters (key fragments, shift mode, etc.).
     *
     * <p>Implementation Requirements:
     * <ul>
     *   <li>Must handle null or empty input arrays gracefully</li>
     *   <li>Should apply transformations according to dynamicShift setting</li>
     *   <li>May optionally use parallel processing based on parallelProcessing setting</li>
     *   <li>Should document any exceptions that might be thrown</li>
     * </ul>
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * byte[] original = "Hello".getBytes(StandardCharsets.UTF_8);
     * byte[] encrypted = encryptor.encrypt(original);
     * }</pre>
     * </p>
     *
     * @param data the original byte array to encrypt
     * @return the encrypted byte array
     * @throws IllegalArgumentException if the input data is malformed
     * @throws IllegalStateException if the encryptor is not properly configured
     * @see #decrypt(byte[])
     * @see #dynamicShift
     * @see #parallelProcessing
     */
    public abstract byte[] encrypt(byte[] data);

    /**
     * Decrypts a byte array.
     * <br/>
     * This abstract method must be implemented by subclasses to provide 
     * specific decryption logic. The method reverses the transformations 
     * applied during encryption to recover the original data.
     *
     * <p>Implementation Requirements:
     * <ul>
     *   <li>Must handle null or empty input arrays gracefully</li>
     *   <li>Should reverse transformations according to dynamicShift setting</li>
     *   <li>May optionally use parallel processing based on parallelProcessing setting</li>
     *   <li>Should document any exceptions that might be thrown</li>
     * </ul>
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * byte[] encrypted = ...; // Previously encrypted data
     * byte[] decrypted = encryptor.decrypt(encrypted);
     * String original = new String(decrypted, StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encryptedData the encrypted byte array to decrypt
     * @return the original byte array
     * @throws IllegalArgumentException if the input data is malformed
     * @throws IllegalStateException if the encryptor is not properly configured
     * @see #encrypt(byte[])
     * @see #dynamicShift
     * @see #parallelProcessing
     */
    public abstract byte[] decrypt(byte[] encryptedData);

    /**
     * Encrypts a ByteBuffer (optional implementation).
     * <br/>
     * Encrypts data stored in a direct ByteBuffer. This method copies data from 
     * the buffer to a temporary array, encrypts it, and writes it back. Subclasses 
     * may override this method for more efficient implementations.
     *
     * <p>Note: This default implementation creates temporary arrays and copies data, 
     * which may impact performance. For better performance, subclasses should 
     * provide optimized implementations that work directly with the buffer.
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * ByteBuffer buffer = ByteBuffer.allocateDirect(1024);
     * // ... populate buffer with data ...
     * boolean success = encryptor.encrypt(buffer, 0, dataLength);
     * }</pre>
     * </p>
     *
     * @param buffer the direct buffer containing the original data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @throws IllegalArgumentException if offset or length are invalid
     * @see #encryptZeroCopy(ByteBuffer, int, int)
     * @see ByteBuffer#isDirect()
     */
    public boolean encrypt(ByteBuffer buffer, int offset, int length) {
        // 默认实现：回退到字节数组操作
        if (buffer == null || !buffer.isDirect() || length <= 0) {
            return false;
        }

        byte[] temp = new byte[length];
        buffer.position(offset);
        buffer.get(temp);
        encrypt(temp);
        buffer.position(offset);
        buffer.put(temp);
        return true;
    }

    /**
     * Zero-copy encryption of ByteBuffer.
     * <br/>
     * Operates directly on the ByteBuffer to avoid additional memory allocation. 
     * This method attempts to perform encryption without copying data to temporary 
     * arrays. Subclasses should override this method for true zero-copy implementations.
     *
     * <p>The default implementation falls back to the regular encryption method. 
     * Subclasses that can work directly with ByteBuffers should override this 
     * method for improved performance.
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * ByteBuffer buffer = ByteBuffer.allocateDirect(1024);
     * // ... populate buffer with data ...
     * boolean success = encryptor.encryptZeroCopy(buffer, 0, dataLength);
     * }</pre>
     * </p>
     *
     * @param buffer the direct buffer containing the original data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #encrypt(ByteBuffer, int, int)
     * @see ByteBuffer#isDirect()
     */
    public boolean encryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 默认实现：回退到常规加密方法
        return encrypt(buffer, offset, length);
    }

    /**
     * Decrypts a ByteBuffer (optional implementation).
     * <br/>
     * Decrypts data stored in a direct ByteBuffer. This method copies data from 
     * the buffer to a temporary array, decrypts it, and writes it back. Subclasses 
     * may override this method for more efficient implementations.
     *
     * <p>Note: This default implementation creates temporary arrays and copies data, 
     * which may impact performance. For better performance, subclasses should 
     * provide optimized implementations that work directly with the buffer.
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * ByteBuffer buffer = ByteBuffer.allocateDirect(1024);
     * // ... populate buffer with encrypted data ...
     * boolean success = decryptor.decrypt(buffer, 0, dataLength);
     * }</pre>
     * </p>
     *
     * @param buffer the direct buffer containing the encrypted data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @throws IllegalArgumentException if offset or length are invalid
     * @see #decryptZeroCopy(ByteBuffer, int, int)
     * @see ByteBuffer#isDirect()
     */
    public boolean decrypt(ByteBuffer buffer, int offset, int length) {
        // 默认实现：回退到字节数组操作
        if (buffer == null || !buffer.isDirect() || length <= 0) {
            return false;
        }

        byte[] temp = new byte[length];
        buffer.position(offset);
        buffer.get(temp);
        decrypt(temp);
        buffer.position(offset);
        buffer.put(temp);
        return true;
    }

    /**
     * Zero-copy decryption of ByteBuffer.
     * <br/>
     * Operates directly on the ByteBuffer to avoid additional memory allocation. 
     * This method attempts to perform decryption without copying data to temporary 
     * arrays. Subclasses should override this method for true zero-copy implementations.
     *
     * <p>The default implementation falls back to the regular decryption method. 
     * Subclasses that can work directly with ByteBuffers should override this 
     * method for improved performance.
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * ByteBuffer buffer = ByteBuffer.allocateDirect(1024);
     * // ... populate buffer with encrypted data ...
     * boolean success = decryptor.decryptZeroCopy(buffer, 0, dataLength);
     * }</pre>
     * </p>
     *
     * @param buffer the direct buffer containing the encrypted data
     * @param offset the data offset
     * @param length the data length
     * @return execution result, true for success, false for failure
     * @see #decrypt(ByteBuffer, int, int)
     * @see ByteBuffer#isDirect()
     */
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 默认实现：回退到常规解密方法
        return decrypt(buffer, offset, length);
    }

    /**
     * Encrypts a byte array and returns a Base64 encoded string.
     * <br/>
     * This convenience method combines encryption with Base64 encoding to produce 
     * a string representation of the encrypted data. This is useful for storing 
     * or transmitting encrypted data in text formats.
     *
     * <p>The method creates a copy of the input data to avoid modifying the original 
     * array, then encrypts the copy and encodes it using Base64.
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * String original = "Hello World";
     * String encrypted = encryptor.encryptBase64(original.getBytes(StandardCharsets.UTF_8));
     * // encrypted now contains a Base64-encoded string of the encrypted data
     * }</pre>
     * </p>
     *
     * @param data the original byte array
     * @return Base64 encoded encrypted string
     * @throws IllegalArgumentException if the input data is null
     * @see #encrypt(byte[])
     * @see Base64#getEncoder()
     * @see #decryptStr(String)
     */
    public String encryptBase64(byte[] data) {
        if (data == null || data.length == 0) return null;

        // 创建副本以避免修改原始数据
        byte[] dataCopy = new byte[data.length];
        System.arraycopy(data, 0, dataCopy, 0, data.length);

        encrypt(dataCopy);
        return Base64.getEncoder().encodeToString(dataCopy);
    }

    /**
     * Decrypts a Base64 encoded string.
     * <br/>
     * This convenience method decodes a Base64 string and then decrypts the 
     * resulting byte array, returning the original string using the configured 
     * character encoding.
     *
     * <p>This method is the counterpart to {@link #encryptBase64(byte[])}, completing 
     * the encrypt-encode/decode-decrypt cycle for string data.
     * </p>
     *
     * <p>Usage example:
     * <pre>{@code
     * String encrypted = ...; // Base64-encoded encrypted data
     * String decrypted = decryptor.decryptStr(encrypted);
     * // decrypted now contains the original string
     * }</pre>
     * </p>
     *
     * @param base64Text Base64 encoded encrypted string
     * @return the decrypted original string
     * @throws IllegalArgumentException if the input string is not valid Base64
     * @see #decrypt(byte[])
     * @see Base64#getDecoder()
     * @see #encryptBase64(byte[])
     * @see #encoding
     */
    public String decryptStr(String base64Text) {
        byte[] decryptedData = Base64.getDecoder().decode(base64Text);
        decrypt(decryptedData);
        return new String(decryptedData, encoding);
    }

    /**
     * Gets a builder instance.
     * <br/>
     * Returns a new FastBlurBuilder instance that can be used to configure and 
     * create FastBlur instances with specific settings. This is the recommended 
     * way to create FastBlur instances.
     *
     * <p>Usage example:
     * <pre>{@code
     * FastBlurBase encryptor = FastBlurBase.builder()
     *     .withEncoding(StandardCharsets.UTF_8)
     *     .withStrategy(FastBlurStrategy.SPEED_FIRST)
     *     .withParallelProcessing(true)
     *     .build();
     * }
     * </pre>
     * </p>
     *
     * @return FastBlurBuilder instance
     * @see FastBlurBuilder
     */
    public static FastBlurBuilder builder() {
        return new FastBlurBuilder();
    }

    /**
     * FastBlur builder class.
     * <br/>
     * Used to build FastBlur instances with different strategies and configurations. 
     * The builder pattern allows for flexible and readable construction of FastBlur 
     * instances with various options.
     *
     * <p>Design Philosophy:
     * The builder pattern separates the complex construction logic from the 
     * FastBlur classes themselves, making it easier to add new configuration 
     * options without complicating constructors.
     * </p>
     *
     * @see FastBlurBase
     * @see FastBlurStrategy
     */
    public static class FastBlurBuilder {

        /**
         * Character encoding to use, defaults to UTF-8.
         * <br/>
         * Determines how strings are converted to byte arrays for encryption and 
         * back to strings after decryption.
         *
         * @see #withEncoding(Charset)
         * @see StandardCharsets
         */
        private Charset encoding = StandardCharsets.UTF_8;
        
        /**
         * Strategy to use for FastBlur implementation, defaults to MEMORY_FIRST.
         * <br/>
         * Different strategies offer various trade-offs between memory usage, 
         * processing speed, and other performance characteristics.
         *
         * @see #withStrategy(FastBlurStrategy)
         * @see FastBlurStrategy
         */
        private FastBlurStrategy strategy = FastBlurStrategy.MEMORY_FIRST;
        
        /**
         * Whether to use dynamic shifting, defaults to true.
         * <br/>
         * Dynamic shifting varies the bit shift amount based on byte position, 
         * providing better obfuscation than fixed shifting.
         *
         * @see #withDynamicShift(boolean)
         * @see FastBlurBase#dynamicShift
         */
        private boolean dynamicShift = true;
        
        /**
         * Whether to enable parallel processing, defaults to false.
         * <br/>
         * Enables parallel processing for large data sets to improve performance 
         * on multi-core systems.
         *
         * @see #withParallelProcessing(boolean)
         * @see FastBlurBase#parallelProcessing
         */
        private boolean parallelProcessing = false;
        
        /**
         * Secret key for dynamic shifting algorithms, defaults to 0x5A7B9C1D3E8F0A2BL.
         * <br/>
         * This 64-bit key is used in dynamic shifting modes to generate key fragments 
         * and shift masks.
         *
         * @see #withSecretKey(long)
         */
        private long secretKey = 0x5A7B9C1D3E8F0A2BL;
        
        /**
         * Key segment for dynamic shifting algorithms, derived from secretKey by default.
         * <br/>
         * This byte value is extracted from the secret key and used in dynamic 
         * shift calculations.
         *
         * @see #withKeySegment(byte)
         */
        private byte keySegment = (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF);
        
        /**
         * Simple key for fixed shifting algorithms, defaults to (byte) 0xAB.
         * <br/>
         * This key is used in fixed shifting modes for XOR operations.
         *
         * @see #withSimpleKey(byte)
         */
        private byte simpleKey = (byte) 0xAB;
        
        /**
         * Fixed shift value for fixed shifting algorithms, defaults to 3.
         * <br/>
         * This value determines how many bit positions each byte is shifted in 
         * fixed shift mode. It is constrained to 0-7 since we're working with 
         * 8-bit values.
         *
         * @see #withShiftValue(int)
         */
        private int shiftValue = 3;

        /**
         * Sets the character encoding method.
         * <br/>
         * Configures the character encoding to be used when converting between 
         * strings and byte arrays during encryption and decryption operations.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withEncoding(StandardCharsets.UTF_16)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param encoding character encoding method
         * @return the builder instance for method chaining
         * @see Charset
         * @see StandardCharsets
         */
        public FastBlurBuilder withEncoding(Charset encoding) {
            this.encoding = encoding;
            return this;
        }

        /**
         * Sets the strategy type.
         * <br/>
         * Configures which FastBlur implementation strategy to use. Different 
         * strategies offer various trade-offs between memory usage and processing speed.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withStrategy(FastBlurStrategy.SPEED_FIRST)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param strategy strategy type
         * @return the builder instance for method chaining
         * @see FastBlurStrategy
         */
        public FastBlurBuilder withStrategy(FastBlurStrategy strategy) {
            this.strategy = strategy;
            return this;
        }

        /**
         * Sets whether to use dynamic shifting.
         * <br/>
         * When enabled, the bit shift amount varies based on the position of each 
         * byte in the data array. This provides better obfuscation compared to 
         * fixed shifting.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withDynamicShift(false) // Use fixed shifting instead
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param dynamicShift true to use dynamic shift, false to use fixed shift
         * @return the builder instance for method chaining
         * @see FastBlurBase#dynamicShift
         */
        public FastBlurBuilder withDynamicShift(boolean dynamicShift) {
            this.dynamicShift = dynamicShift;
            return this;
        }

        /**
         * Sets whether to enable parallel processing.
         * <br/>
         * When enabled, large data sets will be processed using parallel computing 
         * techniques to improve performance on multi-core systems.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withParallelProcessing(true)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param parallelProcessing true to enable parallel processing
         * @return the builder instance for method chaining
         * @see FastBlurBase#parallelProcessing
         */
        public FastBlurBuilder withParallelProcessing(boolean parallelProcessing) {
            this.parallelProcessing = parallelProcessing;
            return this;
        }

        /**
         * Checks whether parallel processing is enabled.
         * <br/>
         * Returns the current setting for parallel processing. This can be used 
         * to check the configuration before building the FastBlur instance.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBuilder builder = FastBlurBase.builder().withParallelProcessing(true);
         * if (builder.isParallelProcessing()) {
         *     // Handle parallel processing enabled case
         * }
         * FastBlurBase encryptor = builder.build();
         * }
         * </pre>
         * </p>
         *
         * @return true if parallel processing is enabled, false otherwise
         * @see #withParallelProcessing(boolean)
         */
        public boolean isParallelProcessing() {
            return parallelProcessing;
        }

        /**
         * Sets the secret key (used for dynamic shift algorithms).
         * <br/>
         * Configures the 64-bit secret key used in dynamic shifting modes to 
         * generate key fragments and shift masks.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withSecretKey(0x123456789ABCDEF0L)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param secretKey 64-bit secret key
         * @return the builder instance for method chaining
         * @see #withKeySegment(byte)
         */
        public FastBlurBuilder withSecretKey(long secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        /**
         * Sets the key segment value (used for dynamic shift algorithms).
         * <br/>
         * Configures the key segment byte value used in dynamic shift calculations. 
         * This is typically extracted from the secret key but can be customized.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withKeySegment((byte) 0xCD)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param keySegment key segment value
         * @return the builder instance for method chaining
         * @see #withSecretKey(long)
         */
        public FastBlurBuilder withKeySegment(byte keySegment) {
            this.keySegment = keySegment;
            return this;
        }

        /**
         * Sets the simple key (used for fixed shift algorithms).
         * <br/>
         * Configures the simple key byte used for XOR operations in fixed shifting modes.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withSimpleKey((byte) 0xEF)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param simpleKey simple key
         * @return the builder instance for method chaining
         * @see #withShiftValue(int)
         */
        public FastBlurBuilder withSimpleKey(byte simpleKey) {
            this.simpleKey = simpleKey;
            return this;
        }

        /**
         * Sets the shift value (used for fixed shift algorithms).
         * <br/>
         * Configures the fixed shift value used in fixed shift mode. This value 
         * determines how many bit positions each byte is shifted. Values are 
         * automatically constrained to the range 0-7.
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withShiftValue(5)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @param shiftValue shift value (automatically constrained to 0-7)
         * @return the builder instance for method chaining
         * @see #withSimpleKey(byte)
         */
        public FastBlurBuilder withShiftValue(int shiftValue) {
            this.shiftValue = shiftValue & 0x7;
            return this;
        }

        /**
         * Builds a FastBlur instance.
         * <br/>
         * Creates a FastBlur instance based on the current configuration. The 
         * specific implementation is selected based on the configured strategy 
         * and options.
         *
         * <p>Implementation Selection Logic:
         * <ul>
         *   <li>{@link FastBlurStrategy#SPEED_FIRST} with dynamic shift -> {@link FastBlurUltra}</li>
         *   <li>{@link FastBlurStrategy#SPEED_FIRST} with fixed shift -> {@link FastBlurSimple}</li>
         *   <li>{@link FastBlurStrategy#VECTOR} with dynamic shift -> {@link FastBlurVectorized}</li>
         *   <li>{@link FastBlurStrategy#VECTOR} with fixed shift -> {@link FastBlurSimple}</li>
         *   <li>{@link FastBlurStrategy#ADAPTIVE} -> {@link FastBlurAdaptive}</li>
         *   <li>{@link FastBlurStrategy#MEMORY_FIRST} with dynamic shift -> {@link FastBlurOptimized}</li>
         *   <li>{@link FastBlurStrategy#MEMORY_FIRST} with fixed shift -> {@link FastBlurSimple}</li>
         * </ul>
         * </p>
         *
         * <p>Usage example:
         * <pre>{@code
         * FastBlurBase encryptor = FastBlurBase.builder()
         *     .withEncoding(StandardCharsets.UTF_8)
         *     .withStrategy(FastBlurStrategy.MEMORY_FIRST)
         *     .withDynamicShift(true)
         *     .build();
         * }
         * </pre>
         * </p>
         *
         * @return FastBlurBase instance
         * @see FastBlurStrategy
         * @see FastBlurUltra
         * @see FastBlurSimple
         * @see FastBlurVectorized
         * @see FastBlurAdaptive
         * @see FastBlurOptimized
         */
        public FastBlurBase build() {
            switch (strategy) {
                case SPEED_FIRST:
                    if (dynamicShift) {
                        return new cn.hehouhui.fastblur.FastBlurUltra(encoding, secretKey, keySegment, parallelProcessing);
                    } else {
                        return new cn.hehouhui.fastblur.FastBlurSimple(encoding, simpleKey, shiftValue, parallelProcessing);
                    }
                case VECTOR:
                    if (dynamicShift) {
                        return new cn.hehouhui.fastblur.FastBlurVectorized(encoding, secretKey, keySegment, parallelProcessing);
                    } else {
                        return new cn.hehouhui.fastblur.FastBlurSimple(encoding, simpleKey, shiftValue, parallelProcessing);
                    }
                case ADAPTIVE:
                    return new cn.hehouhui.fastblur.FastBlurAdaptive(encoding, secretKey, keySegment, parallelProcessing);
                case MEMORY_FIRST:
                default:
                    if (dynamicShift) {
                        return new cn.hehouhui.fastblur.FastBlurOptimized(encoding, secretKey, keySegment, parallelProcessing);
                    } else {
                        return new cn.hehouhui.fastblur.FastBlurSimple(encoding, simpleKey, shiftValue, parallelProcessing);
                    }
            }
        }
    }
}