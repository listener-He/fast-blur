package cn.hehouhui.fastblur;

import java.util.Arrays;
import java.util.Random;

/**
 * FastBlur策略间兼容性测试类
 * 验证不同策略（包括并行和非并行模式）之间的加密解密兼容性
 */
public class FastBlurCompatibilityTest {

    public static void main(String[] args) {
        System.out.println("=== FastBlur策略间兼容性测试 ===");

        // 生成测试数据
        byte[] testData = generateTestData(1000);
        System.out.println("测试数据大小: " + testData.length + " 字节");

        // 测试不同策略间的兼容性
        testCrossStrategyCompatibility(testData);

        // 测试并行与串行模式的兼容性
        testParallelSerialCompatibility(testData);
    }

    /**
     * 测试不同策略间的兼容性
     */
    private static void testCrossStrategyCompatibility(byte[] testData) {
        System.out.println("\n--- 不同策略间兼容性测试 ---");

        // 创建不同策略实例（都使用动态位移）
        FastBlurBase memoryFirst = FastBlurBase.builder()
            .withStrategy(cn.hehouhui.fastblur.FastBlurStrategy.MEMORY_FIRST)
            .withDynamicShift(true)
            .build();

        FastBlurBase speedFirst = FastBlurBase.builder()
            .withStrategy(cn.hehouhui.fastblur.FastBlurStrategy.SPEED_FIRST)
            .withDynamicShift(true)
            .build();

        FastBlurBase vector = FastBlurBase.builder()
            .withStrategy(cn.hehouhui.fastblur.FastBlurStrategy.VECTOR)
            .withDynamicShift(true)
            .build();



        // 使用MemoryFirst策略加密
        byte[] encrypted = memoryFirst.encrypt(testData.clone());
        System.out.println("使用MemoryFirst策略加密完成");

        // 尝试用其他策略解密
        boolean speedFirstDecryptSuccess = testDecrypt(speedFirst, encrypted, testData, "SpeedFirst");
        boolean vectorDecryptSuccess = testDecrypt(vector, encrypted, testData, "Vector");

        boolean allCompatible = speedFirstDecryptSuccess && vectorDecryptSuccess;
        System.out.println("跨策略兼容性: " + (allCompatible ? "通过" : "失败"));
    }

    /**
     * 测试并行与串行模式的兼容性
     */
    private static void testParallelSerialCompatibility(byte[] testData) {
        System.out.println("\n--- 并行与串行模式兼容性测试 ---");

        // 创建串行模式策略
        FastBlurBase serialStrategy = FastBlurBase.builder()
            .withStrategy(cn.hehouhui.fastblur.FastBlurStrategy.VECTOR)
            .withDynamicShift(true)
            .withParallelProcessing(false)
            .build();

        // 创建并行模式策略
        FastBlurBase parallelStrategy = FastBlurBase.builder()
            .withStrategy(cn.hehouhui.fastblur.FastBlurStrategy.VECTOR)
            .withDynamicShift(true)
            .withParallelProcessing(true)
            .build();

        // 使用串行模式加密
        byte[] serialEncrypted = serialStrategy.encrypt(testData.clone());
        System.out.println("使用串行模式加密完成");

        // 使用并行模式解密
        boolean parallelDecryptSuccess = testDecrypt(parallelStrategy, serialEncrypted, testData, "并行模式");

        // 使用并行模式加密
        byte[] parallelEncrypted = parallelStrategy.encrypt(testData.clone());
        System.out.println("使用并行模式加密完成");

        // 使用串行模式解密
        boolean serialDecryptSuccess = testDecrypt(serialStrategy, parallelEncrypted, testData, "串行模式");

        boolean compatible = parallelDecryptSuccess && serialDecryptSuccess;
        System.out.println("并行/串行兼容性: " + (compatible ? "通过" : "失败"));
    }

    /**
     * 测试解密功能
     */
    private static boolean testDecrypt(FastBlurBase strategy, byte[] encryptedData, byte[] originalData, String strategyName) {
        try {
            byte[] decrypted = strategy.decrypt(encryptedData.clone());
            boolean success = Arrays.equals(decrypted, originalData);
            System.out.println(strategyName + "解密: " + (success ? "成功" : "失败"));
            return success;
        } catch (Exception e) {
            System.out.println(strategyName + "解密: 异常 - " + e.getMessage());
            return false;
        }
    }

    private static byte[] generateTestData(int size) {
        byte[] data = new byte[size];
        Random random = new Random(42); // 固定种子以确保测试一致性
        random.nextBytes(data);
        return data;
    }
}
