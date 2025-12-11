package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * 简单轻量的混淆算法（自适应优化版）
 * 高性能可逆轻量级加密工具（动态位移增强混淆，不保证安全性）
 * 核心：动态位移+异或位运算，极快、可逆、混淆性优于固定位移
 *
 * <p>该类提供了一种简单的数据混淆机制，通过动态位移和异或运算实现可逆的数据变换。
 * 根据数据大小自动选择最优的处理策略，适用于各种场景下的高性能数据保护。</p>
 *
 * <p>自适应优化策略：
 * 1. 小数据（≤256字节）：使用查找表优化版本
 * 2. 中等数据（256-2048字节）：使用向量化优化版本
 * 3. 大数据（>2048字节）：使用原始优化版本
 * </p>
 *
 * <p>示例用法：
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
 */
public class FastBlurAdaptive extends FastBlurBase {

    /**
     * 极速版本实例（用于小数据处理）
     */
    private final cn.hehouhui.fastblur.FastBlurUltra fastVersion;

    /**
     * 向量化版本实例（用于中等数据处理）
     */
    private final cn.hehouhui.fastblur.FastBlurVectorized vectorizedVersion;

    /**
     * 优化版本实例（用于大数据处理）
     */
    private final cn.hehouhui.fastblur.FastBlurOptimized optimizedVersion;

    /**
     * 默认构造函数，使用UTF-8字符集编码
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive();
     * }</pre>
     * </p>
     */
    public FastBlurAdaptive() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * 构造函数，使用指定的编码方式初始化FastBlurAdaptive实例
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding 字符编码方式
     */
    public FastBlurAdaptive(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF));
    }

    /**
     * 构造函数，使用指定的编码、密钥和密钥分段初始化FastBlurAdaptive实例
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding   字符编码方式
     * @param key        64位密钥
     * @param keySegment 密钥分段值，用于动态位移计算
     */
    public FastBlurAdaptive(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, false);
    }

    /**
     * 构造函数，使用指定的编码、密钥、密钥分段和平行处理选项初始化FastBlurAdaptive实例
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurAdaptive blur = new FastBlurAdaptive(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
     * }</pre>
     * </p>
     *
     * @param encoding           字符编码方式
     * @param key                64位密钥
     * @param keySegment         密钥分段值，用于动态位移计算
     * @param parallelProcessing 是否启用并行处理
     */
    public FastBlurAdaptive(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        super(encoding, parallelProcessing);
        // 初始化各个版本的实例
        this.fastVersion = new cn.hehouhui.fastblur.FastBlurUltra(encoding, key, keySegment, parallelProcessing);
        this.vectorizedVersion = new cn.hehouhui.fastblur.FastBlurVectorized(encoding, key, keySegment, parallelProcessing);
        this.optimizedVersion = new cn.hehouhui.fastblur.FastBlurOptimized(encoding, key, keySegment, parallelProcessing);
    }

    /**
     * 自适应加密字节数组
     * 根据数据大小选择最优的加密策略
     *
     * @param data 原始字节数组
     *
     * @return 加密后字节数组
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
        } else if (data.length <= 2048) {
            // 中等数据使用向量化版本
            return vectorizedVersion.encrypt(data);
        } else {
            // 大数据使用优化版本
            return optimizedVersion.encrypt(data);
        }
    }

    /**
     * 自适应解密字节数组
     * 根据数据大小选择最优的解密策略
     *
     * @param encryptedData 加密后的字节数组
     *
     * @return 原始字节数组
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
        } else if (encryptedData.length <= 2048) {
            // 中等数据使用向量化版本
            return vectorizedVersion.decrypt(encryptedData);
        } else {
            // 大数据使用优化版本
            return optimizedVersion.decrypt(encryptedData);
        }
    }

    /**
     * Zero-copy加密ByteBuffer
     * 直接在ByteBuffer上进行操作，避免额外的内存分配
     *
     * @param buffer 包含原始数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     *
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
     *
     * @return 执行结果，true表示成功，false表示失败
     */
    @Override
    public boolean decryptZeroCopy(ByteBuffer buffer, int offset, int length) {
        // 回退到常规解密方法
        return decrypt(buffer, offset, length);
    }
}
