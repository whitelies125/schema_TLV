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

// 共用 C schema；调用方负责布局、类型、辅助成员关系及生命周期正确。
// 测长、编码和解码均不分配堆内存；编码输入与输出不得重叠，失败输出应丢弃。
result<std::size_t> encode_size(const tlv_message_schema_t &schema, const void *input);
result<std::size_t> encode(const tlv_message_schema_t &schema, const void *input,
                         std::span<std::uint8_t> output);

// 不整体初始化输出；缺失字段保留原值，数组按已有 count 追加。
// 重复标量覆盖；单值 MESSAGE 合并到同一对象，只有数组才追加元素。
// union 同分支沿用现有内容，切换分支时先初始化新分支。
// 有 presence 但未设置时视为无有效分支，否则已有 choice 须对应已初始化的分支。
// 解码失败可能部分修改输出，应丢弃结果；空 span 表示空 payload。
result<void> decode(const tlv_message_schema_t &schema, std::span<const std::uint8_t> input,
                    void *output, std::size_t output_size);

// 对象重载仅补齐地址和大小，不对 schema 进行完整布局校验。
// 排除指针和数组，避免把对象指针误当成消息本身。
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
