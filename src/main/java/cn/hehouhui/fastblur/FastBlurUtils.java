package cn.hehouhui.fastblur;

/**
 * Utility class for FastBlur operations.
 * <br/>
 * Provides common utility methods used in encryption and decryption operations 
 * throughout the FastBlur library. These methods handle low-level bit manipulation 
 * operations that are fundamental to the FastBlur algorithm.
 *
 * <p>Design Philosophy:
 * This utility class centralizes common bit manipulation operations to ensure 
 * consistent behavior and optimal performance across all FastBlur implementations.
 * All methods are static and the class is not meant to be instantiated.</p>
 *
 * <p>Usage example:
 * <pre>{@code
 * int shiftedValue = FastBlurUtils.rotateLeft(originalValue, shiftAmount);
 * int dynamicShift = FastBlurUtils.getDynamicShift(index, mask);
 * }</pre>
 * </p>
 *
 * @author HeHui
 * @since 1.0
 * @see FastBlurBase
 */
public class FastBlurUtils {
    
    /**
     * Private constructor to prevent instantiation.
     * <br/>
     * This is a utility class containing only static methods, so instantiation 
     * is not allowed. Attempting to create an instance will result in an exception.
     *
     * @throws AssertionError when called, as this class should not be instantiated
     */
    private FastBlurUtils() {
        throw new AssertionError("工具类不允许实例化");
    }
    
    /**
     * Performs a circular left shift operation on a byte value.
     * <br/>
     * This method shifts the bits of a value to the left, wrapping bits that "fall off" 
     * the left end around to the right end. The operation is performed on an 8-bit 
     * value (byte).
     *
     * <p>Example:
     * <pre>{@code
     * // Shift value 0b11001010 left by 2 positions
     * // Result: 0b00101011
     * int result = FastBlurUtils.rotateLeft(0b11001010, 2);
     * }</pre>
     * </p>
     *
     * @param value the value to shift (treated as an 8-bit unsigned value)
     * @param shift the number of positions to shift left (0-7)
     * @return the result after performing the circular left shift
     * @see #rotateRight(int, int)
     */
    public static int rotateLeft(int value, int shift) {
        if (shift == 0) {
            return value;
        }
        return ((value << shift) | (value >>> (8 - shift))) & 0xFF;
    }
    
    /**
     * Performs a circular right shift operation on a byte value.
     * <br/>
     * This method shifts the bits of a value to the right, wrapping bits that "fall off" 
     * the right end around to the left end. The operation is performed on an 8-bit 
     * value (byte).
     *
     * <p>Example:
     * <pre>{@code
     * // Shift value 0b11001010 right by 2 positions
     * // Result: 0b10110010
     * int result = FastBlurUtils.rotateRight(0b11001010, 2);
     * }</pre>
     * </p>
     *
     * @param value the value to shift (treated as an 8-bit unsigned value)
     * @param shift the number of positions to shift right (0-7)
     * @return the result after performing the circular right shift
     * @see #rotateLeft(int, int)
     */
    public static int rotateRight(int value, int shift) {
        if (shift == 0) {
            return value;
        }
        return ((value >>> shift) | (value << (8 - shift))) & 0xFF;
    }
    
    /**
     * Dynamically calculates shift amount based on index and mask.
     * <br/>
     * This method computes a dynamic shift value used in the FastBlur algorithm 
     * to vary the bit shifting operation based on the position of the byte being 
     * processed. This adds complexity to the encryption and makes it more resistant 
     * to certain types of cryptanalysis.
     *
     * <p>Example:
     * <pre>{@code
     * // Calculate dynamic shift for byte at index 5 with mask 0x3F
     * int shift = FastBlurUtils.getDynamicShift(5, 0x3F);
     * }</pre>
     * </p>
     *
     * @param index the array index of the byte being processed
     * @param shiftMask the mask used to calculate the shift value
     * @return a shift value between 0-7
     */
    public static int getDynamicShift(int index, int shiftMask) {
        return (index + shiftMask) & 0x7;
    }
}