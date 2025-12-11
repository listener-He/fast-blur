package cn.hehouhui.fastblur;

import java.util.Arrays;
import java.util.Random;

/**
 * FastBlur策略一致性验证测试类
 * 验证各种策略在相同输入下的结果一致性
 */
public class FastBlurConsistencyTest {

    public static void main(String[] args) {
        System.out.println("=== FastBlur策略一致性验证 ===");

        // 生成测试数据
        byte[] testData = generateTestData(1000);
        System.out.println("测试数据大小: " + testData.length + " 字节");

        // 创建各种策略实例（使用相同配置以便比较）
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



        // 加密数据
        byte[] originalData = testData.clone();
        byte[] encryptedByMemoryFirst = memoryFirst.encrypt(testData.clone());
        byte[] encryptedBySpeedFirst = speedFirst.encrypt(originalData.clone());
        byte[] encryptedByVector = vector.encrypt(originalData.clone());

        // 验证加密结果一致性
        boolean encryptionConsistent =
            Arrays.equals(encryptedByMemoryFirst, encryptedBySpeedFirst) &&
            Arrays.equals(encryptedBySpeedFirst, encryptedByVector);

        System.out.println("加密结果一致性: " + (encryptionConsistent ? "通过" : "失败"));

        // 解密数据并验证一致性
        byte[] decryptedByMemoryFirst = memoryFirst.decrypt(encryptedByMemoryFirst);
        byte[] decryptedBySpeedFirst = speedFirst.decrypt(encryptedBySpeedFirst);
        byte[] decryptedByVector = vector.decrypt(encryptedByVector);

        // 验证解密结果一致性
        boolean decryptionConsistent =
            Arrays.equals(decryptedByMemoryFirst, decryptedBySpeedFirst) &&
            Arrays.equals(decryptedBySpeedFirst, decryptedByVector) &&
            Arrays.equals(decryptedByMemoryFirst, originalData);

        System.out.println("解密结果一致性: " + (decryptionConsistent ? "通过" : "失败"));
        System.out.println("原始数据恢复: " + (Arrays.equals(decryptedByMemoryFirst, originalData) ? "通过" : "失败"));

        // 如果不一致，显示详细信息
        if (!encryptionConsistent || !decryptionConsistent) {
            System.out.println("详细对比:");
            System.out.println("  MemoryFirst 加密结果长度: " + encryptedByMemoryFirst.length);
            System.out.println("  SpeedFirst 加密结果长度: " + encryptedBySpeedFirst.length);
            System.out.println("  Vector 加密结果长度: " + encryptedByVector.length);

            // 显示前几个字节的差异
            System.out.println("前10个字节对比:");
            for (int i = 0; i < Math.min(10, encryptedByMemoryFirst.length); i++) {
                System.out.printf("  [%d] MF: %d, SF: %d, V: %d",
                    i,
                    encryptedByMemoryFirst[i],
                    encryptedBySpeedFirst[i],
                    encryptedByVector[i]);
            }
        } else {
            System.out.println("所有策略结果一致，测试通过！");
        }
    }

    private static byte[] generateTestData(int size) {
        byte[] data = new byte[size];
        Random random = new Random(42); // 固定种子以确保测试一致性
        random.nextBytes(data);
        return data;
    }
}
