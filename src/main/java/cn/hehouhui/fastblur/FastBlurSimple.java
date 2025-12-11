package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

/**
 * 简单轻量的混淆算法（简化版）
 * 高性能可逆轻量级加密工具（固定位移增强混淆，不保证安全性）
 * 核心：固定位移+异或位运算，极快、可逆、混淆性优于固定位移
 * 
 * <p>该类提供了一种简单的数据混淆机制，通过固定位移和异或运算实现可逆的数据变换。
 * 相比复杂版本进行了算法简化，适用于需要极致性能的轻量级数据保护场景。</p>
 * 
 * <p>简化优化点：
 * 1. 使用固定位移替代动态位移计算
 * 2. 减少加密步骤，只进行一次异或和一次位移操作
 * 3. 支持并行处理大数据块
 * </p>
 *
 * <p>示例用法：
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
 */
public class FastBlurSimple extends FastBlurBase {

    /**
     * 预计算的密钥（用于异或运算）
     */
    private final byte key;
    
    /**
     * 固定位移值
     */
    private final int shift;
    
    /**
     * 是否启用并行处理
     */
    private final boolean parallelProcessing;

    /**
     * 默认构造函数，使用UTF-8字符集编码
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurSimple blur = new FastBlurSimple();
     * }</pre>
     * </p>
     */
    public FastBlurSimple() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * 构造函数，使用指定的编码方式初始化FastBlurSimple实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurSimple blur = new FastBlurSimple(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding 字符编码方式
     */
    public FastBlurSimple(Charset encoding) {
        this(encoding, (byte) 0xAB, 3, false);
    }

    /**
     * 构造函数，使用指定的编码、密钥和位移值初始化FastBlurSimple实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurSimple blur = new FastBlurSimple(StandardCharsets.UTF_8, (byte) 0xCD, 5);
     * }</pre>
     * </p>
     *
     * @param encoding 字符编码方式
     * @param key      用于异或运算的密钥
     * @param shift    固定位移值（0-7之间）
     */
    public FastBlurSimple(Charset encoding, byte key, int shift) {
        this(encoding, key, shift, false);
    }

    /**
     * 构造函数，使用指定的编码、密钥、位移值和平行处理选项初始化FastBlurSimple实例
     * 
     * @param encoding          字符编码方式
     * @param key               用于异或运算的密钥
     * @param shift             固定位移值（0-7之间）
     * @param parallelProcessing 是否启用并行处理
     */
    public FastBlurSimple(Charset encoding, byte key, int shift, boolean parallelProcessing) {
        super(encoding);
        this.key = key;
        this.shift = shift & 0x7; // 确保位移值在0-7之间
        this.parallelProcessing = parallelProcessing;
    }

    /**
     * 简化加密字节数组（固定位移增强混淆）
     * 
     * <p>简化加密过程只有两个步骤：
     * 1. 使用密钥与数据进行异或运算
     * 2. 对结果进行固定循环左移</p>
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurSimple encryptor = new FastBlurSimple();
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

        // 根据配置决定是否使用并行处理
        if (parallelProcessing && data.length >= 8192) {
            return encryptParallel(data);
        }

        // 直接在原数组上操作，避免数组复制开销
        for (int i = 0; i < data.length; i++) {
            // 步骤1：密钥异或
            data[i] ^= key;
            
            // 步骤2：固定循环左移
            if (shift != 0) {
                int unsigned = data[i] & 0xFF;
                int shifted = (unsigned << shift) | (unsigned >>> (8 - shift));
                data[i] = (byte) (shifted & 0xFF);
            }
        }
        return data;
    }

    /**
     * 简化解密字节数组（加密的逆操作，固定位移还原）
     * 
     * <p>简化解密是加密的逆向操作：
     * 1. 对数据进行固定循环右移
     * 2. 使用密钥与数据进行异或运算</p>
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurSimple encryptor = new FastBlurSimple();
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

        // 根据配置决定是否使用并行处理
        if (parallelProcessing && encryptedData.length >= 8192) {
            return decryptParallel(encryptedData);
        }

        // 直接在原数组上操作，避免数组复制开销
        for (int i = 0; i < encryptedData.length; i++) {
            // 逆步骤2：固定循环右移
            if (shift != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                int shifted = (unsigned >>> shift) | (unsigned << (8 - shift));
                encryptedData[i] = (byte) (shifted & 0xFF);
            }
            
            // 逆步骤1：密钥异或
            encryptedData[i] ^= key;
        }
        return encryptedData;
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
        if (data == null || data.length == 0) {
            return data;
        }
        
        // 创建数据副本以避免修改原始数据
        byte[] dataCopy = new byte[data.length];
        System.arraycopy(data, 0, dataCopy, 0, data.length);
        
        // 使用ForkJoin框架进行并行处理
        ForkJoinPool pool = new ForkJoinPool();
        try {
            pool.invoke(new EncryptTask(dataCopy, 0, dataCopy.length, key, shift));
        } finally {
            pool.shutdown();
        }
        
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
        if (encryptedData == null || encryptedData.length == 0) {
            return encryptedData;
        }
        
        // 创建数据副本以避免修改原始数据
        byte[] dataCopy = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0, dataCopy, 0, encryptedData.length);
        
        // 使用ForkJoin框架进行并行处理
        ForkJoinPool pool = new ForkJoinPool();
        try {
            pool.invoke(new DecryptTask(dataCopy, 0, dataCopy.length, key, shift));
        } finally {
            pool.shutdown();
        }
        
        return dataCopy;
    }

    /**
     * 加密ByteBuffer（可选实现）
     *
     * @param buffer 包含原始数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
     */
    @Override
    public boolean encrypt(ByteBuffer buffer, int offset, int length) {
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
            b ^= key;
            if (shift != 0) {
                int unsigned = b & 0xFF;
                int shifted = (unsigned << shift) | (unsigned >>> (8 - shift));
                b = (byte) (shifted & 0xFF);
            }
            buffer.put(i, b);
        }
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
            b ^= key;
            if (shift != 0) {
                int unsigned = b & 0xFF;
                int shifted = (unsigned << shift) | (unsigned >>> (8 - shift));
                b = (byte) (shifted & 0xFF);
            }
            buffer.put(i, b);
        }
        return true;
    }

    /**
     * 解密ByteBuffer（可选实现）
     *
     * @param buffer 包含加密数据的直接缓冲区
     * @param offset 数据偏移量
     * @param length 数据长度
     * @return 执行结果，true表示成功，false表示失败
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
                int shifted = (unsigned >>> shift) | (unsigned << (8 - shift));
                b = (byte) (shifted & 0xFF);
            }
            b ^= key;
            buffer.put(i, b);
        }
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
                int shifted = (unsigned >>> shift) | (unsigned << (8 - shift));
                b = (byte) (shifted & 0xFF);
            }
            b ^= key;
            buffer.put(i, b);
        }
        return true;
    }

    /**
     * 加密任务（用于并行处理）
     */
    private static class EncryptTask extends RecursiveAction {
        private static final int THRESHOLD = 8192; // 任务阈值：8KB
        private final byte[] data;
        private final int start;
        private final int end;
        private final byte key;
        private final int shift;

        EncryptTask(byte[] data, int start, int end, byte key, int shift) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.key = key;
            this.shift = shift;
        }

        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    data[i] ^= key;
                    if (shift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = (unsigned << shift) | (unsigned >>> (8 - shift));
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
     * 解密任务（用于并行处理）
     */
    private static class DecryptTask extends RecursiveAction {
        private static final int THRESHOLD = 8192; // 任务阈值：8KB
        private final byte[] data;
        private final int start;
        private final int end;
        private final byte key;
        private final int shift;

        DecryptTask(byte[] data, int start, int end, byte key, int shift) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.key = key;
            this.shift = shift;
        }

        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    if (shift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = (unsigned >>> shift) | (unsigned << (8 - shift));
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
