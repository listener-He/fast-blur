package cn.hehouhui.fastblur;


import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 简单轻量的混淆算法基类
 * 高性能可逆轻量级加密工具（动态位移增强混淆，不保证安全性）
 * 核心：位移+异或位运算，可逆、混淆性优于固定位移
 *
 * <p>该类提供了一种简单的数据混淆机制基类，通过位移和异或运算实现可逆的数据变换。
 * 子类可以实现不同的优化策略来满足特定的性能需求。</p>
 *
 * <p>使用示例：
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
 */
public abstract class FastBlurBase {

    /**
     * 字符编码方式，默认使用UTF-8
     */
    protected final Charset encoding;

    /**
     * 是否启用并行处理
     */
    protected final boolean parallelProcessing;

    /**
     * 构造函数，使用默认UTF-8编码
     */
    protected FastBlurBase() {
        this(StandardCharsets.UTF_8, false);
    }

    /**
     * 构造函数，使用指定编码
     *
     * @param encoding 字符编码方式
     */
    protected FastBlurBase(Charset encoding) {
        this(encoding, false);
    }

    /**
     * 构造函数，使用指定编码和平行处理选项
     *
     * @param encoding 字符编码方式
     * @param parallelProcessing 是否启用并行处理
     */
    protected FastBlurBase(Charset encoding, boolean parallelProcessing) {
        this.encoding = encoding;
        this.parallelProcessing = parallelProcessing;
    }

    /**
     * 加密字节数组
     *
     * @param data 原始字节数组
     * @return 加密后字节数组
     */
    public abstract byte[] encrypt(byte[] data);

    /**
     * 解密字节数组
     *
     * @param encryptedData 加密后的字节数组
     * @return 原始字节数组
     */
    public abstract byte[] decrypt(byte[] encryptedData);

    /**
     * 加密ByteBuffer（可选实现）
     *
     * @param buffer 包含原始数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
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
     * Zero-copy加密ByteBuffer
     * 直接在ByteBuffer上进行操作，避免额外的内存分配
     *
     * @param buffer 包含原始数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
     */
    public boolean encryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 默认实现：回退到常规加密方法
        return encrypt(buffer, offset, length);
    }

    /**
     * 解密ByteBuffer（可选实现）
     *
     * @param buffer 包含加密数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
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
     * Zero-copy解密ByteBuffer
     * 直接在ByteBuffer上进行操作，避免额外的内存分配
     *
     * @param buffer 包含加密数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
     */
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 默认实现：回退到常规解密方法
        return decrypt(buffer, offset, length);
    }

    /**
     * 加密字节数组并返回Base64编码的字符串
     *
     * @param data 原始字节数组
     * @return Base64编码的加密字符串
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
     * 解密Base64编码的字符串
     *
     * @param base64Text Base64编码的加密字符串
     * @return 解密后的原始字符串
     */
    public String decryptStr(String base64Text) {
        byte[] decryptedData = Base64.getDecoder().decode(base64Text);
        decrypt(decryptedData);
        return new String(decryptedData, encoding);
    }

    /**
     * 获取构建器实例
     *
     * @return FastBlurBuilder实例
     */
    public static FastBlurBuilder builder() {
        return new FastBlurBuilder();
    }

    /**
     * FastBlur构建器类
     * 用于构建不同策略的FastBlur实例
     */
    public static class FastBlurBuilder {

        private Charset encoding = StandardCharsets.UTF_8;
        private FastBlurStrategy strategy = FastBlurStrategy.MEMORY_FIRST;
        private boolean dynamicShift = true;
        private boolean parallelProcessing = false;
        private long secretKey = 0x5A7B9C1D3E8F0A2BL;
        private byte keySegment = (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF);
        private byte simpleKey = (byte) 0xAB;
        private int shiftValue = 3;

        /**
         * 设置字符编码方式
         *
         * @param encoding 字符编码方式
         * @return 构建器实例
         */
        public FastBlurBuilder withEncoding(Charset encoding) {
            this.encoding = encoding;
            return this;
        }

        /**
         * 设置策略类型
         *
         * @param strategy 策略类型
         * @return 构建器实例
         */
        public FastBlurBuilder withStrategy(FastBlurStrategy strategy) {
            this.strategy = strategy;
            return this;
        }

        /**
         * 设置是否使用动态位移
         *
         * @param dynamicShift true表示使用动态位移，false表示使用固定位移
         * @return 构建器实例
         */
        public FastBlurBuilder withDynamicShift(boolean dynamicShift) {
            this.dynamicShift = dynamicShift;
            return this;
        }

        /**
         * 设置是否启用并行处理
         *
         * @param parallelProcessing true表示启用并行处理
         * @return 构建器实例
         */
        public FastBlurBuilder withParallelProcessing(boolean parallelProcessing) {
            this.parallelProcessing = parallelProcessing;
            return this;
        }

        /**
         * 检查是否启用并行处理
         *
         * @return true表示启用并行处理，false表示未启用
         */
        public boolean isParallelProcessing() {
            return parallelProcessing;
        }

        /**
         * 设置密钥（用于动态位移算法）
         *
         * @param secretKey 64位密钥
         * @return 构建器实例
         */
        public FastBlurBuilder withSecretKey(long secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        /**
         * 设置密钥分段值（用于动态位移算法）
         *
         * @param keySegment 密钥分段值
         * @return 构建器实例
         */
        public FastBlurBuilder withKeySegment(byte keySegment) {
            this.keySegment = keySegment;
            return this;
        }

        /**
         * 设置简单密钥（用于固定位移算法）
         *
         * @param simpleKey 简单密钥
         * @return 构建器实例
         */
        public FastBlurBuilder withSimpleKey(byte simpleKey) {
            this.simpleKey = simpleKey;
            return this;
        }

        /**
         * 设置位移值（用于固定位移算法）
         *
         * @param shiftValue 位移值（0-7之间）
         * @return 构建器实例
         */
        public FastBlurBuilder withShiftValue(int shiftValue) {
            this.shiftValue = shiftValue & 0x7;
            return this;
        }

        /**
         * 构建FastBlur实例
         *
         * @return FastBlurBase实例
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
