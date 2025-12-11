package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

/**
 * 简单轻量的混淆算法（优化版）
 * 高性能可逆轻量级加密工具（动态位移增强混淆，不保证安全性）
 * 核心：动态位移+异或位运算，极快、可逆、混淆性优于固定位移
 * 
 * <p>该类提供了一种简单的数据混淆机制，通过动态位移和异或运算实现可逆的数据变换。
 * 相比原版进行了多项性能优化，适用于需要极致性能的轻量级数据保护场景。</p>
 * 
 * <p>优化点：
 * 1. 内联位移操作避免函数调用开销
 * 2. 预计算密钥片段避免重复计算
 * 3. 减少不必要的数组复制操作
 * 4. 使用位运算替代取模运算
 * </p>
 *
 * <p>示例用法：
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
 */
public class FastBlurOptimized extends FastBlurBase {
    
    
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
     * 默认构造函数，使用UTF-8字符集编码
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized();
     * }</pre>
     * </p>
     */
    public FastBlurOptimized() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * 构造函数，使用指定的编码方式初始化FastBlurOptimized实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding 字符编码方式
     */
    public FastBlurOptimized(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF));
    }

    /**
     * 构造函数，使用指定的编码、密钥和密钥分段初始化FastBlurOptimized实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding    字符编码方式
     * @param key         64位密钥
     * @param keySegment  密钥分段值，用于动态位移计算
     */
    public FastBlurOptimized(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, false);
    }

    /**
     * 构造函数，使用指定的编码、密钥、密钥分段和平行处理选项初始化FastBlurOptimized实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
     * }</pre>
     * </p>
     *
     * @param encoding           字符编码方式
     * @param key                64位密钥
     * @param keySegment         密钥分段值，用于动态位移计算
     * @param parallelProcessing 是否启用并行处理
     */
    public FastBlurOptimized(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        super(encoding, parallelProcessing);
        // 预计算密钥片段，避免在每次加密/解密时重复计算
        this.keyPart1 = (byte) (key & 0xFF);
        this.keyPart2 = (byte) ((key >> 8) & 0xFF);
        this.shiftMask = keySegment & 0xFF;
    }

    /**
     * 动态计算位移位数（核心增强点）
     * 
     * <p>根据字节索引和密钥分段值动态计算位移位数，确保结果在0-7之间。
     * 这种动态计算增加了算法的复杂度和安全性。</p>
     *
     * <p>示例用法：
     * <pre>{@code
     * FastBlurOptimized blur = new FastBlurOptimized();
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
     * FastBlurOptimized encryptor = new FastBlurOptimized();
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

        // 如果启用了并行处理且数据足够大，则使用并行处理
        if (parallelProcessing && data.length >= 16384) {
            return encryptParallel(data);
        }

        // 对于小数据(<=128字节)，使用展开循环优化
        if (data.length <= 128) {
            return encryptUnrolled(data);
        }

        // 直接在原数组上操作，避免数组复制开销
        for (int i = 0; i < data.length; i++) {
            int dynamicShift = getDynamicShift(i);
            
            // 步骤1：第一段密钥异或
            data[i] ^= keyPart1;
            
            // 步骤2：动态循环左移（内联操作避免函数调用开销）
            if (dynamicShift != 0) {
                int unsigned = data[i] & 0xFF;
                int shifted = (unsigned << dynamicShift) | (unsigned >>> (8 - dynamicShift));
                data[i] = (byte) (shifted & 0xFF);
            }
            
            // 步骤3：第二段密钥异或
            data[i] ^= keyPart2;
        }
        return data;
    }

    /**
     * 展开循环的小数据加密方法
     * 专门为小数据(<=128字节)优化性能
     *
     * @param data 原始字节数组
     * @return 加密后字节数组
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
            int dynamicShift0 = (i + mask) & 0x7;
            data[i] ^= kp1;
            if (dynamicShift0 != 0) {
                int unsigned = data[i] & 0xFF;
                data[i] = (byte) (((unsigned << dynamicShift0) | (unsigned >>> (8 - dynamicShift0))) & 0xFF);
            }
            data[i] ^= kp2;
            
            int dynamicShift1 = ((i + 1) + mask) & 0x7;
            data[i+1] ^= kp1;
            if (dynamicShift1 != 0) {
                int unsigned = data[i+1] & 0xFF;
                data[i+1] = (byte) (((unsigned << dynamicShift1) | (unsigned >>> (8 - dynamicShift1))) & 0xFF);
            }
            data[i+1] ^= kp2;
            
            int dynamicShift2 = ((i + 2) + mask) & 0x7;
            data[i+2] ^= kp1;
            if (dynamicShift2 != 0) {
                int unsigned = data[i+2] & 0xFF;
                data[i+2] = (byte) (((unsigned << dynamicShift2) | (unsigned >>> (8 - dynamicShift2))) & 0xFF);
            }
            data[i+2] ^= kp2;
            
            int dynamicShift3 = ((i + 3) + mask) & 0x7;
            data[i+3] ^= kp1;
            if (dynamicShift3 != 0) {
                int unsigned = data[i+3] & 0xFF;
                data[i+3] = (byte) (((unsigned << dynamicShift3) | (unsigned >>> (8 - dynamicShift3))) & 0xFF);
            }
            data[i+3] ^= kp2;
        }
        
        // 处理剩余字节
        for (; i < len; i++) {
            int dynamicShift = (i + mask) & 0x7;
            data[i] ^= kp1;
            if (dynamicShift != 0) {
                int unsigned = data[i] & 0xFF;
                data[i] = (byte) (((unsigned << dynamicShift) | (unsigned >>> (8 - dynamicShift))) & 0xFF);
            }
            data[i] ^= kp2;
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
     * FastBlurOptimized encryptor = new FastBlurOptimized();
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

        // 对于小数据(<=128字节)，使用展开循环优化
        if (encryptedData.length <= 128) {
            return decryptUnrolled(encryptedData);
        }

        // 直接在原数组上操作，避免数组复制开销
        for (int i = 0; i < encryptedData.length; i++) {
            int dynamicShift = getDynamicShift(i);
            
            // 逆步骤3：第二段密钥异或还原
            encryptedData[i] ^= keyPart2;
            
            // 逆步骤2：动态循环右移（内联操作避免函数调用开销）
            if (dynamicShift != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                int shifted = (unsigned >>> dynamicShift) | (unsigned << (8 - dynamicShift));
                encryptedData[i] = (byte) (shifted & 0xFF);
            }
            
            // 逆步骤1：第一段密钥异或还原
            encryptedData[i] ^= keyPart1;
        }
        return encryptedData;
    }

    /**
     * 展开循环的小数据解密方法
     * 专门为小数据(<=128字节)优化性能
     *
     * @param encryptedData 加密后的字节数组
     * @return 原始字节数组
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
            int dynamicShift0 = (i + mask) & 0x7;
            encryptedData[i] ^= kp2;
            if (dynamicShift0 != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (((unsigned >>> dynamicShift0) | (unsigned << (8 - dynamicShift0))) & 0xFF);
            }
            encryptedData[i] ^= kp1;
            
            int dynamicShift1 = ((i + 1) + mask) & 0x7;
            encryptedData[i+1] ^= kp2;
            if (dynamicShift1 != 0) {
                int unsigned = encryptedData[i+1] & 0xFF;
                encryptedData[i+1] = (byte) (((unsigned >>> dynamicShift1) | (unsigned << (8 - dynamicShift1))) & 0xFF);
            }
            encryptedData[i+1] ^= kp1;
            
            int dynamicShift2 = ((i + 2) + mask) & 0x7;
            encryptedData[i+2] ^= kp2;
            if (dynamicShift2 != 0) {
                int unsigned = encryptedData[i+2] & 0xFF;
                encryptedData[i+2] = (byte) (((unsigned >>> dynamicShift2) | (unsigned << (8 - dynamicShift2))) & 0xFF);
            }
            encryptedData[i+2] ^= kp1;
            
            int dynamicShift3 = ((i + 3) + mask) & 0x7;
            encryptedData[i+3] ^= kp2;
            if (dynamicShift3 != 0) {
                int unsigned = encryptedData[i+3] & 0xFF;
                encryptedData[i+3] = (byte) (((unsigned >>> dynamicShift3) | (unsigned << (8 - dynamicShift3))) & 0xFF);
            }
            encryptedData[i+3] ^= kp1;
        }
        
        // 处理剩余字节
        for (; i < len; i++) {
            int dynamicShift = (i + mask) & 0x7;
            encryptedData[i] ^= kp2;
            if (dynamicShift != 0) {
                int unsigned = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (((unsigned >>> dynamicShift) | (unsigned << (8 - dynamicShift))) & 0xFF);
            }
            encryptedData[i] ^= kp1;
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
        // 使用公共ForkJoin框架进行并行处理，避免频繁创建销毁线程池
        ForkJoinPool.commonPool().invoke(new EncryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask));
        
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
        // 使用公共ForkJoin框架进行并行处理，避免频繁创建销毁线程池
        ForkJoinPool.commonPool().invoke(new DecryptTask(dataCopy, 0, dataCopy.length, keyPart1, keyPart2, shiftMask));
        
        return dataCopy;
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
     * 加密任务（用于并行处理）
     */
    private static class EncryptTask extends RecursiveAction {
        private static final int THRESHOLD = 16384; // 任务阈值：16KB
        private static final long serialVersionUID = -5048830231452146650L;
        private final byte[] data;
        private final int start;
        private final int end;
        private final byte keyPart1;
        private final byte keyPart2;
        private final int shiftMask;

        EncryptTask(byte[] data, int start, int end, byte keyPart1, byte keyPart2, int shiftMask) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.keyPart1 = keyPart1;
            this.keyPart2 = keyPart2;
            this.shiftMask = shiftMask;
        }

        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    int dynamicShift = (i + shiftMask) & 0x7;
                    
                    // 步骤1：第一段密钥异或
                    data[i] ^= keyPart1;
                    
                    // 步骤2：动态循环左移
                    if (dynamicShift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = (unsigned << dynamicShift) | (unsigned >>> (8 - dynamicShift));
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
     * 解密任务（用于并行处理）
     */
    private static class DecryptTask extends RecursiveAction {
        private static final int THRESHOLD = 16384; // 任务阈值：16KB
        private static final long serialVersionUID = 4586245996695330434L;
        private final byte[] data;
        private final int start;
        private final int end;
        private final byte keyPart1;
        private final byte keyPart2;
        private final int shiftMask;

        DecryptTask(byte[] data, int start, int end, byte keyPart1, byte keyPart2, int shiftMask) {
            this.data = data;
            this.start = start;
            this.end = end;
            this.keyPart1 = keyPart1;
            this.keyPart2 = keyPart2;
            this.shiftMask = shiftMask;
        }

        @Override
        protected void compute() {
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                for (int i = start; i < end; i++) {
                    int dynamicShift = (i + shiftMask) & 0x7;
                    
                    // 逆步骤3：第二段密钥异或还原
                    data[i] ^= keyPart2;
                    
                    // 逆步骤2：动态循环右移
                    if (dynamicShift != 0) {
                        int unsigned = data[i] & 0xFF;
                        int shifted = (unsigned >>> dynamicShift) | (unsigned << (8 - dynamicShift));
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
