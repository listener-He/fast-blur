package cn.hehouhui.fastblur;

/**
 * Performance optimization strategy enumeration for FastBlur algorithms.
 * <br/>
 * This enum defines different performance optimization strategies that can be used 
 * with FastBlur implementations. Each strategy represents a trade-off between 
 * memory usage, processing speed, and other performance characteristics.
 *
 * <p>Design Philosophy:</p>
 * <ul>
 *   <li>{@link #MEMORY_FIRST} - Balanced approach optimizing for memory efficiency</li>
 *   <li>{@link #SPEED_FIRST} - Maximum speed optimization at the cost of higher memory usage</li>
 *   <li>{@link #VECTOR} - Vectorized processing for bulk data operations</li>
 *   <li>{@link #ADAPTIVE} - Automatically selects the best strategy based on data size</li>
 * </ul>
 *
 * @author HeHui
 * @since 1.0
 * @see FastBlurBase
 * @see FastBlurBase.FastBlurBuilder
 */
public enum FastBlurStrategy {

    /**
     * Memory-first strategy.
     * <br/>
     * Balances memory usage and processing speed, suitable for most application scenarios.
     * This strategy aims to minimize memory footprint while maintaining reasonable 
     * processing performance.
     *
     * <p>Use case: General purpose applications where memory conservation is important 
     * but high throughput is not critical.</p>
     */
    MEMORY_FIRST,

    /**
     * Speed-first strategy.
     * <br/>
     * Maximizes processing speed using techniques like lookup tables, but consumes 
     * more memory. This strategy pre-calculates values to reduce computation time.
     *
     * <p>Use case: Applications requiring maximum processing speed where memory 
     * usage is not a primary concern.</p>
     */
    SPEED_FIRST,

    /**
     * Vector processing strategy.
     * <br/>
     * Uses vectorized processing techniques to optimize handling of large volumes 
     * of data. This strategy processes data in batches to improve throughput.
     *
     * <p>Use case: Processing large datasets where batch operations can significantly 
     * improve performance.</p>
     */
    VECTOR,

    /**
     * Adaptive strategy.
     * <br/>
     * Automatically selects the most suitable processing strategy based on data size.
     * It dynamically chooses between different algorithms depending on the amount 
     * of data being processed.
     *
     * <p>Use case: Applications handling varying data sizes where a single strategy 
     * may not be optimal for all cases.</p>
     *
     * @see FastBlurAdaptive
     */
    ADAPTIVE
}
