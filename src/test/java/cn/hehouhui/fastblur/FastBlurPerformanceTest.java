package cn.hehouhui.fastblur;

import java.util.Random;

/**
 * FastBlur性能测试类
 * 测试各种策略在不同数据大小和配置下的性能表现
 */
public class FastBlurPerformanceTest {

    public static void main(String[] args) {
        // 测试不同大小的数据
        int[] sizes = {100, 1000, 10000, 100000, 1000000};

        for (int size : sizes) {
            System.out.println("测试数据大小: " + size + " 字节");
            testWithSize(size);
            System.out.println();
        }

        // 验证各策略结果一致性
        System.out.println("=== 策略结果一致性验证 ===");
        validateStrategyConsistency();
    }

    private static void testWithSize(int size) {
        // 生成测试数据
        byte[] testData = generateTestData(size);

        // 测试各种策略
        testStrategy("简单策略(串行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.MEMORY_FIRST)
            .withDynamicShift(false)
            .build(), testData);

        testStrategy("简单策略(并行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.MEMORY_FIRST)
            .withDynamicShift(false)
            .withParallelProcessing(true)
            .build(), testData);

        testStrategy("优化策略(串行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.MEMORY_FIRST)
            .withDynamicShift(true)
            .build(), testData);

        testStrategy("优化策略(并行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.MEMORY_FIRST)
            .withDynamicShift(true)
            .withParallelProcessing(true)
            .build(), testData);

        testStrategy("极速策略(串行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.SPEED_FIRST)
            .withDynamicShift(true)
            .build(), testData);

        testStrategy("极速策略(并行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.SPEED_FIRST)
            .withDynamicShift(true)
            .withParallelProcessing(true)
            .build(), testData);

        testStrategy("向量策略(串行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.VECTOR)
            .withDynamicShift(true)
            .build(), testData);

        testStrategy("向量策略(并行)", FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.VECTOR)
            .withDynamicShift(true)
            .withParallelProcessing(true)
            .build(), testData);

    }

    private static void testStrategy(String name, FastBlurBase blur, byte[] data) {
        // 复制测试数据以避免修改原始数据
        byte[] testData = new byte[data.length];
        System.arraycopy(data, 0, testData, 0, data.length);

        // 预热
        for (int i = 0; i < 3; i++) {
            blur.encrypt(testData.clone());
        }

        // 性能测试
        long startTime = System.nanoTime();
        int iterations = Math.max(1, 1000000 / data.length); // 调整迭代次数以适应数据大小
        for (int i = 0; i < iterations; i++) {
            blur.encrypt(testData.clone());
        }
        long endTime = System.nanoTime();

        long duration = (endTime - startTime) / 1000000; // 转换为毫秒
        System.out.printf("%-20s: %d ms (%d iterations)%n", name, duration, iterations);
    }

    private static byte[] generateTestData(int size) {
        byte[] data = new byte[size];
        Random random = new Random(42); // 固定种子以确保测试一致性
        random.nextBytes(data);
        return data;
    }

    /**
     * 验证各策略在相同输入下的结果一致性
     */
    private static void validateStrategyConsistency() {
        // 使用固定大小的测试数据
        byte[] testData = generateTestData(1000);

        // 创建各种策略实例（使用相同配置以便比较）
        FastBlurBase memoryFirst = FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.MEMORY_FIRST)
            .withDynamicShift(true)
            .build();

        FastBlurBase speedFirst = FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.SPEED_FIRST)
            .withDynamicShift(true)
            .build();

        FastBlurBase vector = FastBlurBase.builder()
            .withStrategy(FastBlurStrategy.VECTOR)
            .withDynamicShift(true)
            .build();



        // 加密数据
        byte[] encryptedByMemoryFirst = memoryFirst.encrypt(testData.clone());
        byte[] encryptedBySpeedFirst = speedFirst.encrypt(testData.clone());
        byte[] encryptedByVector = vector.encrypt(testData.clone());

        // 验证加密结果一致性
        boolean encryptionConsistent =
            java.util.Arrays.equals(encryptedByMemoryFirst, encryptedBySpeedFirst) &&
            java.util.Arrays.equals(encryptedBySpeedFirst, encryptedByVector);
        System.out.println("加密结果一致性: " + (encryptionConsistent ? "通过" : "失败"));

        // 解密数据并验证一致性
        byte[] decryptedByMemoryFirst = memoryFirst.decrypt(encryptedByMemoryFirst);
        byte[] decryptedBySpeedFirst = speedFirst.decrypt(encryptedBySpeedFirst);
        byte[] decryptedByVector = vector.decrypt(encryptedByVector);

        // 验证解密结果一致性
        boolean decryptionConsistent =
            java.util.Arrays.equals(decryptedByMemoryFirst, decryptedBySpeedFirst) &&
            java.util.Arrays.equals(decryptedBySpeedFirst, decryptedByVector) &&
            java.util.Arrays.equals(decryptedByMemoryFirst, testData);

        System.out.println("解密结果一致性: " + (decryptionConsistent ? "通过" : "失败"));
        System.out.println("原始数据恢复: " + (java.util.Arrays.equals(decryptedByMemoryFirst, testData) ? "通过" : "失败"));

        // 如果不一致，显示详细信息
        if (!encryptionConsistent || !decryptionConsistent) {
            System.out.println("详细对比:");
            System.out.println("  MemoryFirst 加密结果长度: " + encryptedByMemoryFirst.length);
            System.out.println("  SpeedFirst 加密结果长度: " + encryptedBySpeedFirst.length);
            System.out.println("  Vector 加密结果长度: " + encryptedByVector.length);
        }
    }
}
