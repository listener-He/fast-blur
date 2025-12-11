package cn.hehouhui.fastblur;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 简单轻量的混淆算法（极速版）
 * 高性能可逆轻量级加密工具（动态位移增强混淆，不保证安全性）
 * 核心：动态位移+异或位运算，极快、可逆、混淆性优于固定位移
 * 
 * <p>该类提供了一种简单的数据混淆机制，通过动态位移和异或运算实现可逆的数据变换。
 * 相比普通版本进行了极致性能优化，适用于需要极致性能的轻量级数据保护场景。</p>
 * 
 * <p>极致优化点：
 * 1. 使用查找表完全避免位运算
 * 2. 展开小规模循环减少分支预测失败
 * 3. 预计算所有可能的位移结果
 * 4. 避免所有不必要的对象创建
 * 5. 利用CPU缓存友好的访问模式
 * </p>
 *
 * <p>示例用法：
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
 */
public class FastBlurUltra extends FastBlurBase {

    /**
     * 字符编码方式，默认使用UTF-8
     */
    private final Charset encoding;
    
    /**
     * 预计算的密钥片段1（用于异或运算）
     */
    private final byte keyPart1;
    
    /**
     * 预计算的密钥片段2（用于异或运算）
     */
    private final byte keyPart2;
    
    /**
     * 用于位移计算的掩码
     */
    private final int shiftMask;
    
    /**
     * 左循环位移查找表
     */
    private final byte[][] leftShiftTable;
    
    /**
     * 右循环位移查找表
     */
    private final byte[][] rightShiftTable;

    /**
     * 默认构造函数，使用UTF-8字符集编码
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra();
     * }</pre>
     * </p>
     */
    public FastBlurUltra() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * 构造函数，使用指定的编码方式初始化FastBlurUltra实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding 字符编码方式
     */
    public FastBlurUltra(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF));
    }

    /**
     * 构造函数，使用指定的编码、密钥和密钥分段初始化FastBlurUltra实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding    字符编码方式
     * @param key         64位密钥
     * @param keySegment  密钥分段值，用于动态位移计算
     */
    public FastBlurUltra(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, false);
    }

    /**
     * 构造函数，使用指定的编码、密钥、密钥分段和平行处理选项初始化FastBlurUltra实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
     * }</pre>
     * </p>
     *
     * @param encoding           字符编码方式
     * @param key                64位密钥
     * @param keySegment         密钥分段值，用于动态位移计算
     * @param parallelProcessing 是否启用并行处理
     */
    public FastBlurUltra(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        super(encoding, parallelProcessing);
        // 预计算密钥片段，避免在每次加密/解密时重复计算
        this.keyPart1 = (byte) (key & 0xFF);
        this.keyPart2 = (byte) ((key >> 8) & 0xFF);
        this.shiftMask = keySegment & 0xFF;
        
        // 预计算查找表
        this.leftShiftTable = new byte[8][256];
        this.rightShiftTable = new byte[8][256];
        
        for (int shift = 0; shift < 8; shift++) {
            for (int b = 0; b < 256; b++) {
                // 左循环位移
                leftShiftTable[shift][b] = (byte) (((b << shift) | (b >>> (8 - shift))) & 0xFF);
                // 右循环位移
                rightShiftTable[shift][b] = (byte) (((b >>> shift) | (b << (8 - shift))) & 0xFF);
            }
        }
    }

    /**
     * 动态计算位移位数（核心增强点）
     * 
     * <p>根据字节索引和密钥分段值动态计算位移位数，确保结果在0-7之间。
     * 这种动态计算增加了算法的复杂度和安全性。</p>
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurUltra blur = new FastBlurUltra();
     * int shift = blur.getDynamicShift(5); // 计算索引为5的字节的位移数
     * }</pre>
     * </p>
     *
     * @param index 字节数组下标
     * @return 0-7之间的位移数
     */
    private int getDynamicShift(int index) {
        // 规则：下标 + 密钥分段值 取模8，保证位移数0-7
        return (index + shiftMask) & 0x7; // 使用位运算代替取模运算，提高性能
    }

    /**
     * 加密字节数组（动态位移增强混淆）
     * 
     * <p>加密过程分为三个步骤：
     * 1. 使用密钥的第一部分与数据进行异或运算
     * 2. 对结果进行动态循环左移
     * 3. 使用密钥的第二部分与数据进行异或运算</p>
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurUltra encryptor = new FastBlurUltra();
     * byte[] original = "Hello".getBytes(StandardCharsets.UTF_8);
     * byte[] encrypted = encryptor.encrypt(original);
     * }</pre>
     * </p>
     *
     * @param data 原始字节数组
     * @return 加密后字节数组
     */
    @Override
    public byte[] encrypt(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }

        // 直接在原数组上操作，避免数组复制开销
        final int len = data.length;
        for (int i = 0; i < len; i++) {
            // 将byte转换为unsigned int以用作查找表索引
            final int b = data[i] & 0xFF;
            
            // 步骤1：第一段密钥异或
            final int xored1 = b ^ (keyPart1 & 0xFF);
            
            // 获取动态位移值
            final int dynamicShift = getDynamicShift(i);
            
            // 步骤2：动态循环左移（使用查找表）
            final int shifted = leftShiftTable[dynamicShift][xored1] & 0xFF;
            
            // 步骤3：第二段密钥异或
            data[i] = (byte) (shifted ^ (keyPart2 & 0xFF));
        }
        return data;
    }

    /**
     * 小数据量快速加密方法（展开循环版本）
     * 专门针对小于等于8字节的数据进行优化
     *
     * @param data 原始字节数组（长度必须<=8）
     * @return 加密后字节数组
     */
    public byte[] encryptSmall(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }
        
        final int len = data.length;
        // 展开小循环以减少分支开销
        switch (len) {
            case 8:
                data[7] = (byte) ((leftShiftTable[getDynamicShift(7)][(data[7] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 7:
                data[6] = (byte) ((leftShiftTable[getDynamicShift(6)][(data[6] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 6:
                data[5] = (byte) ((leftShiftTable[getDynamicShift(5)][(data[5] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 5:
                data[4] = (byte) ((leftShiftTable[getDynamicShift(4)][(data[4] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 4:
                data[3] = (byte) ((leftShiftTable[getDynamicShift(3)][(data[3] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 3:
                data[2] = (byte) ((leftShiftTable[getDynamicShift(2)][(data[2] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 2:
                data[1] = (byte) ((leftShiftTable[getDynamicShift(1)][(data[1] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            case 1:
                data[0] = (byte) ((leftShiftTable[getDynamicShift(0)][(data[0] & 0xFF) ^ (keyPart1 & 0xFF)] & 0xFF) ^ (keyPart2 & 0xFF));
            default:
                // 不应该到达这里
                break;
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

        // 直接在原数组上操作，避免数组复制开销
        final int len = encryptedData.length;
        for (int i = 0; i < len; i++) {
            // 将byte转换为unsigned int以用作查找表索引
            final int b = encryptedData[i] & 0xFF;
            
            // 逆步骤3：第二段密钥异或还原
            final int xored1 = b ^ (keyPart2 & 0xFF);
            
            // 获取动态位移值（使用相同的规则）
            final int dynamicShift = getDynamicShift(i);
            
            // 逆步骤2：动态循环右移（使用查找表）
            final int shifted = rightShiftTable[dynamicShift][xored1] & 0xFF;
            
            // 逆步骤1：第一段密钥异或还原
            encryptedData[i] = (byte) (shifted ^ (keyPart1 & 0xFF));
        }
        return encryptedData;
    }

    /**
     * 小数据量快速解密方法（展开循环版本）
     * 专门针对小于等于8字节的数据进行优化
     *
     * @param encryptedData 加密后的字节数组（长度必须<=8）
     * @return 原始字节数组
     */
    public byte[] decryptSmall(byte[] encryptedData) {
        if (encryptedData == null || encryptedData.length == 0) {
            return encryptedData;
        }
        
        final int len = encryptedData.length;
        // 展开小循环以减少分支开销
        switch (len) {
            case 8:
                encryptedData[7] = (byte) ((rightShiftTable[getDynamicShift(7)][(encryptedData[7] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 7:
                encryptedData[6] = (byte) ((rightShiftTable[getDynamicShift(6)][(encryptedData[6] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 6:
                encryptedData[5] = (byte) ((rightShiftTable[getDynamicShift(5)][(encryptedData[5] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 5:
                encryptedData[4] = (byte) ((rightShiftTable[getDynamicShift(4)][(encryptedData[4] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 4:
                encryptedData[3] = (byte) ((rightShiftTable[getDynamicShift(3)][(encryptedData[3] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 3:
                encryptedData[2] = (byte) ((rightShiftTable[getDynamicShift(2)][(encryptedData[2] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 2:
                encryptedData[1] = (byte) ((rightShiftTable[getDynamicShift(1)][(encryptedData[1] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            case 1:
                encryptedData[0] = (byte) ((rightShiftTable[getDynamicShift(0)][(encryptedData[0] & 0xFF) ^ (keyPart2 & 0xFF)] & 0xFF) ^ (keyPart1 & 0xFF));
            default:
                // 不应该到达这里
                break;
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
}
