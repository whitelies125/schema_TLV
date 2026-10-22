#ifndef SCHEMA_TLV_CPP_H
#define SCHEMA_TLV_CPP_H

#include "tlv_schema.h"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <type_traits>

namespace tlv {
template <class T> using result = std::expected<T, codec_status_t>;

// 与 C 版共用 schema；调用方保证描述与对象布局匹配，描述及其引用在调用期间有效且不变。
// 测长、编码和解码均不分配堆内存；失败通过 std::unexpected 返回 codec_status_t。

// 计算完整消息的编码字节数，不写码流；input 必须指向有效消息对象。
result<std::size_t> encode_size(const tlv_message_schema_t &schema, const void *input);
// 直接编码并返回实际写入字节数，无需预先测长；output 提供可写存储，大小可以超过实际编码长度。
// input 必须有效且在调用期间保持不变，不能与 output 重叠；失败时应丢弃已部分写入的 output。
result<std::size_t> encode(const tlv_message_schema_t &schema, const void *input,
                         std::span<std::uint8_t> output);

// 将 input 中的完整 TLV payload 解码到 output；output 必须有效，output_size 至少为 struct_size。
// 输入码流不得与输出对象重叠；空 span 表示空消息，保持输出对象不变。
// 不整体初始化输出；调用方须准备好对象及 count、choice、presence，从空消息开始时应先初始化整个对象。
// 未知 tag 跳过，缺失字段保留原值；重复整数、BOOL 和字符串覆盖，数组按已有 count 追加。
// 单值 MESSAGE 合并到同一对象，缺失的子字段仍保留；MESSAGE 数组每次追加一个子对象。
// union 同分支沿用现有内容，切换分支时先初始化新分支。
// 有 presence 但未设置时视为无有效分支，否则已有 choice 须对应已初始化的分支。
// 解码失败可能部分修改输出，应丢弃结果。
result<void> decode(const tlv_message_schema_t &schema, std::span<const std::uint8_t> input,
                    void *output, std::size_t output_size);

// 对象重载要求标准布局且可平凡复制；这不代表对象类型与 schema 已匹配。
// 排除指针、数组和 volatile 对象，避免把对象指针本身或不适用的存储当成消息。
template <class T>
concept message_object = std::is_standard_layout_v<T> && std::is_trivially_copyable_v<T>
    && !std::is_pointer_v<T> && !std::is_null_pointer_v<T>
    && !std::is_array_v<T> && !std::is_volatile_v<T>;

template <message_object T>
result<std::size_t> encode_size(const tlv_message_schema_t &schema, const T &input)
{
    if (sizeof(T) < schema.struct_size) return std::unexpected(CODEC_BUFFER_TOO_SMALL);
    return encode_size(schema, static_cast<const void *>(std::addressof(input)));
}

template <message_object T>
result<std::size_t> encode(const tlv_message_schema_t &schema, const T &input,
                         std::span<std::uint8_t> output)
{
    if (sizeof(T) < schema.struct_size) return std::unexpected(CODEC_BUFFER_TOO_SMALL);
    return encode(schema, static_cast<const void *>(std::addressof(input)), output);
}

template <message_object T>
    requires(!std::is_const_v<T>)
result<void> decode(const tlv_message_schema_t &schema, std::span<const std::uint8_t> input,
                    T &output)
{
    return decode(schema, input, static_cast<void *>(std::addressof(output)), sizeof(T));
}
} // namespace tlv
#endif
