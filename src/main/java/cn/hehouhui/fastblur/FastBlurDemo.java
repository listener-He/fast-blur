package cn.hehouhui.fastblur;

import java.nio.charset.StandardCharsets;

/**
 * FastBlur使用示例类
 * 展示如何使用不同的策略和配置来创建和使用FastBlur实例
 *
 * @author HeHui
 * @since 1.0
 */
public class FastBlurDemo {

    public static void main(String[] args) {
        // 1. 使用默认配置创建FastBlur实例（内存优先策略，动态位移）
        FastBlurBase defaultBlur = FastBlurBase.builder().build();
        demoEncryption(defaultBlur, "默认配置（内存优先策略，动态位移）");

        // 2. 使用速度优先策略
        FastBlurBase speedBlur = FastBlurBase.builder()
                .withStrategy(FastBlurStrategy.SPEED_FIRST)
                .build();
        demoEncryption(speedBlur, "速度优先策略，动态位移");

        // 3. 使用向量处理策略
        FastBlurBase vectorBlur = FastBlurBase.builder()
                .withStrategy(FastBlurStrategy.VECTOR)
                .build();
        demoEncryption(vectorBlur, "向量处理策略，动态位移");

        // 4. 使用自适应策略
        FastBlurBase adaptiveBlur = FastBlurBase.builder()
                .withStrategy(FastBlurStrategy.ADAPTIVE)
                .build();
        demoEncryption(adaptiveBlur, "自适应策略，动态位移");

        // 5. 使用固定位移的内存优先策略
        FastBlurBase fixedMemoryBlur = FastBlurBase.builder()
                .withDynamicShift(false)
                .build();
        demoEncryption(fixedMemoryBlur, "内存优先策略，固定位移");

        // 6. 使用固定位移的速度优先策略
        FastBlurBase fixedSpeedBlur = FastBlurBase.builder()
                .withStrategy(FastBlurStrategy.SPEED_FIRST)
                .withDynamicShift(false)
                .build();
        demoEncryption(fixedSpeedBlur, "速度优先策略，固定位移");

        // 7. 使用固定位移的向量处理策略
        FastBlurBase fixedVectorBlur = FastBlurBase.builder()
                .withStrategy(FastBlurStrategy.VECTOR)
                .withDynamicShift(false)
                .build();
        demoEncryption(fixedVectorBlur, "向量处理策略，固定位移");

        // 8. 使用带并行处理的固定位移策略
        FastBlurBase parallelBlur = FastBlurBase.builder()
                .withStrategy(FastBlurStrategy.MEMORY_FIRST)
                .withDynamicShift(false)
                .withParallelProcessing(true)
                .build();
        demoEncryption(parallelBlur, "内存优先策略，固定位移，并行处理");
    }

    /**
     * 演示加密和解密过程
     *
     * @param blur   FastBlur实例
     * @param description 描述信息
     */
    private static void demoEncryption(FastBlurBase blur, String description) {
        System.out.println("=== " + description + " ===");

        String originalText = "这是一段测试文本，用于演示FastBlur的不同实现方式。";
        System.out.println("原始文本: " + originalText);

        // 加密
        String encryptedText = blur.encryptBase64(originalText.getBytes(StandardCharsets.UTF_8));
        System.out.println("加密结果: " + encryptedText);

        // 解密
        String decryptedText = blur.decryptStr(encryptedText);
        System.out.println("解密结果: " + decryptedText);

        // 验证
        boolean isEqual = originalText.equals(decryptedText);
        System.out.println("原始文本与解密文本是否相等: " + isEqual);
        System.out.println();
    }
}
