package cn.hehouhui.fastblur;

/**
 * FastBlur策略枚举
 * 定义了不同的性能优化策略
 *
 * @author HeHui
 * @since 1.0
 */
public enum FastBlurStrategy {

    /**
     * 内存优先策略
     * 在内存使用和处理速度之间取得平衡，适合大多数应用场景
     */
    MEMORY_FIRST,

    /**
     * 速度优先策略
     * 使用查找表等技术最大化处理速度，但会消耗更多内存
     */
    SPEED_FIRST,

    /**
     * 向量处理策略
     * 使用向量化处理技术优化大批量数据的处理
     */
    VECTOR,

    /**
     * 自适应策略
     * 根据数据大小自动选择最适合的处理策略
     */
    ADAPTIVE
}
