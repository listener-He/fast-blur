package cn.hehouhui.fastblur;

/**
 * FastBlur工具类
 * 提供加密解密相关的通用工具方法
 *
 * @author HeHui
 * @since 1.0
 */
public class FastBlurUtils {
    
    /**
     * 私有构造函数，防止实例化
     */
    private FastBlurUtils() {
        throw new AssertionError("工具类不允许实例化");
    }
    
    /**
     * 循环左移操作
     *
     * @param value  要移动的值
     * @param shift  位移数量(0-7)
     * @return 位移后的结果
     */
    public static int rotateLeft(int value, int shift) {
        if (shift == 0) {
            return value;
        }
        return ((value << shift) | (value >>> (8 - shift))) & 0xFF;
    }
    
    /**
     * 循环右移操作
     *
     * @param value  要移动的值
     * @param shift  位移数量(0-7)
     * @return 位移后的结果
     */
    public static int rotateRight(int value, int shift) {
        if (shift == 0) {
            return value;
        }
        return ((value >>> shift) | (value << (8 - shift))) & 0xFF;
    }
    
    /**
     * 动态计算位移位数
     *
     * @param index     字节数组下标
     * @param shiftMask 位移掩码
     * @return 0-7之间的位移数
     */
    public static int getDynamicShift(int index, int shiftMask) {
        return (index + shiftMask) & 0x7;
    }
}