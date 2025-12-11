package cn.hehouhui.fastblur;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

/**
 * 简单轻量的混淆算法（向量化版）
 * 高性能可逆轻量级加密工具（动态位移增强混淆，不保证安全性）
 * 核心：动态位移+异或位运算，极快、可逆、混淆性优于固定位移
 * 
 * <p>该类提供了一种简单的数据混淆机制，通过动态位移和异或运算实现可逆的数据变换。
 * 使用向量化处理思想优化，适用于需要极致性能的轻量级数据保护场景。</p>
 * 
 * <p>向量化优化点：
 * 1. 批量处理数据减少循环开销
 * 2. 减少条件分支提高分支预测准确性
 * 3. 优化内存访问模式提高缓存命中率
 * 4. 使用展开循环减少CPU流水线停顿
 * </p>
 *
 * <p>示例用法：
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
 * @since 1.0
 */
public class FastBlurVectorized extends FastBlurBase {

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
     * FastBlurVectorized blur = new FastBlurVectorized();
     * }</pre>
     * </p>
     */
    public FastBlurVectorized() {
        this(StandardCharsets.UTF_8);
    }

    /**
     * 构造函数，使用指定的编码方式初始化FastBlurVectorized实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurVectorized blur = new FastBlurVectorized(StandardCharsets.UTF_8);
     * }</pre>
     * </p>
     *
     * @param encoding 字符编码方式
     */
    public FastBlurVectorized(Charset encoding) {
        this(encoding, 0x5A7B9C1D3E8F0A2BL, (byte) ((0x5A7B9C1D3E8F0A2BL >> 16) & 0xFF));
    }

    /**
     * 构造函数，使用指定的编码、密钥和密钥分段初始化FastBlurVectorized实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurVectorized blur = new FastBlurVectorized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB);
     * }</pre>
     * </p>
     *
     * @param encoding    字符编码方式
     * @param key         64位密钥
     * @param keySegment  密钥分段值，用于动态位移计算
     */
    public FastBlurVectorized(Charset encoding, long key, byte keySegment) {
        this(encoding, key, keySegment, false);
    }

    /**
     * 构造函数，使用指定的编码、密钥、密钥分段和平行处理选项初始化FastBlurVectorized实例
     * 
     * <p>示例用法：
     * <pre>{@code
     * FastBlurVectorized blur = new FastBlurVectorized(StandardCharsets.UTF_8, 0x123456789ABCDEF0L, (byte) 0xAB, true);
     * }</pre>
     * </p>
     *
     * @param encoding           字符编码方式
     * @param key                64位密钥
     * @param keySegment         密钥分段值，用于动态位移计算
     * @param parallelProcessing 是否启用并行处理
     */
    public FastBlurVectorized(Charset encoding, long key, byte keySegment, boolean parallelProcessing) {
        super(encoding, parallelProcessing);
        // 预计算密钥片段，避免在每次加密/解密时重复计算
        this.keyPart1 = (byte) (key & 0xFF);
        this.keyPart2 = (byte) ((key >> 8) & 0xFF);
        this.shiftMask = keySegment & 0xFF;
    }

    /**
     * 向量化加密字节数组
     * 
     * <p>通过批量处理和减少分支来提升性能</p>
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
        if (parallelProcessing && data.length >= 8192) {
            return encryptParallel(data);
        }

        final int len = data.length;
        final byte kp1 = keyPart1;
        final byte kp2 = keyPart2;
        final int mask = shiftMask;
        
        int i = 0;
        
        // 主循环：每次处理8个字节
        for (; i <= len - 8; i += 8) {
            // 批量计算位移值
            final int s0 = (i + mask) & 0x7;
            final int s1 = ((i + 1) + mask) & 0x7;
            final int s2 = ((i + 2) + mask) & 0x7;
            final int s3 = ((i + 3) + mask) & 0x7;
            final int s4 = ((i + 4) + mask) & 0x7;
            final int s5 = ((i + 5) + mask) & 0x7;
            final int s6 = ((i + 6) + mask) & 0x7;
            final int s7 = ((i + 7) + mask) & 0x7;
            
            // 批量处理加密操作
            data[i] ^= kp1;
            if (s0 != 0) {
                final int u = data[i] & 0xFF;
                data[i] = (byte) (((u << s0) | (u >>> (8 - s0))) & 0xFF);
            }
            data[i] ^= kp2;
            
            data[i+1] ^= kp1;
            if (s1 != 0) {
                final int u = data[i+1] & 0xFF;
                data[i+1] = (byte) (((u << s1) | (u >>> (8 - s1))) & 0xFF);
            }
            data[i+1] ^= kp2;
            
            data[i+2] ^= kp1;
            if (s2 != 0) {
                final int u = data[i+2] & 0xFF;
                data[i+2] = (byte) (((u << s2) | (u >>> (8 - s2))) & 0xFF);
            }
            data[i+2] ^= kp2;
            
            data[i+3] ^= kp1;
            if (s3 != 0) {
                final int u = data[i+3] & 0xFF;
                data[i+3] = (byte) (((u << s3) | (u >>> (8 - s3))) & 0xFF);
            }
            data[i+3] ^= kp2;
            
            data[i+4] ^= kp1;
            if (s4 != 0) {
                final int u = data[i+4] & 0xFF;
                data[i+4] = (byte) (((u << s4) | (u >>> (8 - s4))) & 0xFF);
            }
            data[i+4] ^= kp2;
            
            data[i+5] ^= kp1;
            if (s5 != 0) {
                final int u = data[i+5] & 0xFF;
                data[i+5] = (byte) (((u << s5) | (u >>> (8 - s5))) & 0xFF);
            }
            data[i+5] ^= kp2;
            
            data[i+6] ^= kp1;
            if (s6 != 0) {
                final int u = data[i+6] & 0xFF;
                data[i+6] = (byte) (((u << s6) | (u >>> (8 - s6))) & 0xFF);
            }
            data[i+6] ^= kp2;
            
            data[i+7] ^= kp1;
            if (s7 != 0) {
                final int u = data[i+7] & 0xFF;
                data[i+7] = (byte) (((u << s7) | (u >>> (8 - s7))) & 0xFF);
            }
            data[i+7] ^= kp2;
        }
        
        // 处理剩余不足8个字节的数据
        for (; i < len; i++) {
            final int shift = (i + mask) & 0x7;
            data[i] ^= kp1;
            if (shift != 0) {
                final int u = data[i] & 0xFF;
                data[i] = (byte) (((u << shift) | (u >>> (8 - shift))) & 0xFF);
            }
            data[i] ^= kp2;
        }
        
        return data;
    }

    /**
     * 向量化解密字节数组
     * 
     * <p>通过批量处理和减少分支来提升性能</p>
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
            final int s0 = (i + mask) & 0x7;
            final int s1 = ((i + 1) + mask) & 0x7;
            final int s2 = ((i + 2) + mask) & 0x7;
            final int s3 = ((i + 3) + mask) & 0x7;
            final int s4 = ((i + 4) + mask) & 0x7;
            final int s5 = ((i + 5) + mask) & 0x7;
            final int s6 = ((i + 6) + mask) & 0x7;
            final int s7 = ((i + 7) + mask) & 0x7;
            
            // 批量处理解密操作（逆序执行加密的逆操作）
            encryptedData[i] ^= kp2;
            if (s0 != 0) {
                final int u = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (((u >>> s0) | (u << (8 - s0))) & 0xFF);
            }
            encryptedData[i] ^= kp1;
            
            encryptedData[i+1] ^= kp2;
            if (s1 != 0) {
                final int u = encryptedData[i+1] & 0xFF;
                encryptedData[i+1] = (byte) (((u >>> s1) | (u << (8 - s1))) & 0xFF);
            }
            encryptedData[i+1] ^= kp1;
            
            encryptedData[i+2] ^= kp2;
            if (s2 != 0) {
                final int u = encryptedData[i+2] & 0xFF;
                encryptedData[i+2] = (byte) (((u >>> s2) | (u << (8 - s2))) & 0xFF);
            }
            encryptedData[i+2] ^= kp1;
            
            encryptedData[i+3] ^= kp2;
            if (s3 != 0) {
                final int u = encryptedData[i+3] & 0xFF;
                encryptedData[i+3] = (byte) (((u >>> s3) | (u << (8 - s3))) & 0xFF);
            }
            encryptedData[i+3] ^= kp1;
            
            encryptedData[i+4] ^= kp2;
            if (s4 != 0) {
                final int u = encryptedData[i+4] & 0xFF;
                encryptedData[i+4] = (byte) (((u >>> s4) | (u << (8 - s4))) & 0xFF);
            }
            encryptedData[i+4] ^= kp1;
            
            encryptedData[i+5] ^= kp2;
            if (s5 != 0) {
                final int u = encryptedData[i+5] & 0xFF;
                encryptedData[i+5] = (byte) (((u >>> s5) | (u << (8 - s5))) & 0xFF);
            }
            encryptedData[i+5] ^= kp1;
            
            encryptedData[i+6] ^= kp2;
            if (s6 != 0) {
                final int u = encryptedData[i+6] & 0xFF;
                encryptedData[i+6] = (byte) (((u >>> s6) | (u << (8 - s6))) & 0xFF);
            }
            encryptedData[i+6] ^= kp1;
            
            encryptedData[i+7] ^= kp2;
            if (s7 != 0) {
                final int u = encryptedData[i+7] & 0xFF;
                encryptedData[i+7] = (byte) (((u >>> s7) | (u << (8 - s7))) & 0xFF);
            }
            encryptedData[i+7] ^= kp1;
        }
        
        // 处理剩余不足8个字节的数据
        for (; i < len; i++) {
            final int shift = (i + mask) & 0x7;
            encryptedData[i] ^= kp2;
            if (shift != 0) {
                final int u = encryptedData[i] & 0xFF;
                encryptedData[i] = (byte) (((u >>> shift) | (u << (8 - shift))) & 0xFF);
            }
            encryptedData[i] ^= kp1;
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
     * 加密任务（用于并行处理）
     */
    private static class EncryptTask extends RecursiveAction {
        private static final int THRESHOLD = 4096; // 任务阈值：4KB
        private static final long serialVersionUID = -1134508474606636622L;
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
            final byte kp1 = keyPart1;
            final byte kp2 = keyPart2;
            final int mask = shiftMask;
            
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                int i = start;
                
                // 主循环：每次处理8个字节
                for (; i <= end - 8; i += 8) {
                    // 批量计算位移值
                    final int s0 = (i + mask) & 0x7;
                    final int s1 = ((i + 1) + mask) & 0x7;
                    final int s2 = ((i + 2) + mask) & 0x7;
                    final int s3 = ((i + 3) + mask) & 0x7;
                    final int s4 = ((i + 4) + mask) & 0x7;
                    final int s5 = ((i + 5) + mask) & 0x7;
                    final int s6 = ((i + 6) + mask) & 0x7;
                    final int s7 = ((i + 7) + mask) & 0x7;
                    
                    // 批量处理加密操作
                    data[i] ^= kp1;
                    if (s0 != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (((u << s0) | (u >>> (8 - s0))) & 0xFF);
                    }
                    data[i] ^= kp2;
                    
                    data[i+1] ^= kp1;
                    if (s1 != 0) {
                        final int u = data[i+1] & 0xFF;
                        data[i+1] = (byte) (((u << s1) | (u >>> (8 - s1))) & 0xFF);
                    }
                    data[i+1] ^= kp2;
                    
                    data[i+2] ^= kp1;
                    if (s2 != 0) {
                        final int u = data[i+2] & 0xFF;
                        data[i+2] = (byte) (((u << s2) | (u >>> (8 - s2))) & 0xFF);
                    }
                    data[i+2] ^= kp2;
                    
                    data[i+3] ^= kp1;
                    if (s3 != 0) {
                        final int u = data[i+3] & 0xFF;
                        data[i+3] = (byte) (((u << s3) | (u >>> (8 - s3))) & 0xFF);
                    }
                    data[i+3] ^= kp2;
                    
                    data[i+4] ^= kp1;
                    if (s4 != 0) {
                        final int u = data[i+4] & 0xFF;
                        data[i+4] = (byte) (((u << s4) | (u >>> (8 - s4))) & 0xFF);
                    }
                    data[i+4] ^= kp2;
                    
                    data[i+5] ^= kp1;
                    if (s5 != 0) {
                        final int u = data[i+5] & 0xFF;
                        data[i+5] = (byte) (((u << s5) | (u >>> (8 - s5))) & 0xFF);
                    }
                    data[i+5] ^= kp2;
                    
                    data[i+6] ^= kp1;
                    if (s6 != 0) {
                        final int u = data[i+6] & 0xFF;
                        data[i+6] = (byte) (((u << s6) | (u >>> (8 - s6))) & 0xFF);
                    }
                    data[i+6] ^= kp2;
                    
                    data[i+7] ^= kp1;
                    if (s7 != 0) {
                        final int u = data[i+7] & 0xFF;
                        data[i+7] = (byte) (((u << s7) | (u >>> (8 - s7))) & 0xFF);
                    }
                    data[i+7] ^= kp2;
                }
                
                // 处理剩余不足8个字节的数据
                for (; i < end; i++) {
                    final int shift = (i + mask) & 0x7;
                    data[i] ^= kp1;
                    if (shift != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (((u << shift) | (u >>> (8 - shift))) & 0xFF);
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
     * 解密任务（用于并行处理）
     */
    private static class DecryptTask extends RecursiveAction {
        private static final int THRESHOLD = 4096; // 任务阈值：4KB
        private static final long serialVersionUID = 6527346346469821233L;
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
            final byte kp1 = keyPart1;
            final byte kp2 = keyPart2;
            final int mask = shiftMask;
            
            if (end - start <= THRESHOLD) {
                // 直接处理数据块
                int i = start;
                
                // 主循环：每次处理8个字节
                for (; i <= end - 8; i += 8) {
                    // 批量计算位移值
                    final int s0 = (i + mask) & 0x7;
                    final int s1 = ((i + 1) + mask) & 0x7;
                    final int s2 = ((i + 2) + mask) & 0x7;
                    final int s3 = ((i + 3) + mask) & 0x7;
                    final int s4 = ((i + 4) + mask) & 0x7;
                    final int s5 = ((i + 5) + mask) & 0x7;
                    final int s6 = ((i + 6) + mask) & 0x7;
                    final int s7 = ((i + 7) + mask) & 0x7;
                    
                    // 批量处理解密操作（逆序执行加密的逆操作）
                    data[i] ^= kp2;
                    if (s0 != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (((u >>> s0) | (u << (8 - s0))) & 0xFF);
                    }
                    data[i] ^= kp1;
                    
                    data[i+1] ^= kp2;
                    if (s1 != 0) {
                        final int u = data[i+1] & 0xFF;
                        data[i+1] = (byte) (((u >>> s1) | (u << (8 - s1))) & 0xFF);
                    }
                    data[i+1] ^= kp1;
                    
                    data[i+2] ^= kp2;
                    if (s2 != 0) {
                        final int u = data[i+2] & 0xFF;
                        data[i+2] = (byte) (((u >>> s2) | (u << (8 - s2))) & 0xFF);
                    }
                    data[i+2] ^= kp1;
                    
                    data[i+3] ^= kp2;
                    if (s3 != 0) {
                        final int u = data[i+3] & 0xFF;
                        data[i+3] = (byte) (((u >>> s3) | (u << (8 - s3))) & 0xFF);
                    }
                    data[i+3] ^= kp1;
                    
                    data[i+4] ^= kp2;
                    if (s4 != 0) {
                        final int u = data[i+4] & 0xFF;
                        data[i+4] = (byte) (((u >>> s4) | (u << (8 - s4))) & 0xFF);
                    }
                    data[i+4] ^= kp1;
                    
                    data[i+5] ^= kp2;
                    if (s5 != 0) {
                        final int u = data[i+5] & 0xFF;
                        data[i+5] = (byte) (((u >>> s5) | (u << (8 - s5))) & 0xFF);
                    }
                    data[i+5] ^= kp1;
                    
                    data[i+6] ^= kp2;
                    if (s6 != 0) {
                        final int u = data[i+6] & 0xFF;
                        data[i+6] = (byte) (((u >>> s6) | (u << (8 - s6))) & 0xFF);
                    }
                    data[i+6] ^= kp1;
                    
                    data[i+7] ^= kp2;
                    if (s7 != 0) {
                        final int u = data[i+7] & 0xFF;
                        data[i+7] = (byte) (((u >>> s7) | (u << (8 - s7))) & 0xFF);
                    }
                    data[i+7] ^= kp1;
                }
                
                // 处理剩余不足8个字节的数据
                for (; i < end; i++) {
                    final int shift = (i + mask) & 0x7;
                    data[i] ^= kp2;
                    if (shift != 0) {
                        final int u = data[i] & 0xFF;
                        data[i] = (byte) (((u >>> shift) | (u << (8 - shift))) & 0xFF);
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
