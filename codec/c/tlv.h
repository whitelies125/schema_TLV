#ifndef TLV_H
#define TLV_H

#include "tlv_schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 编解码接口的共同约定：
 * - 调用方负责 schema 的布局、类型、容量和组合语义正确且符合预期。
 * - schema 及其引用的描述在使用期间必须有效且保持不变。
 * - 库不检查布局重叠、辅助成员共享等关系，不保证任意描述组合都能正确往返编解码。
 * - 非法描述不保证被发现或安全失败；消息值、码流长度、输出容量和溢出仍在运行时检查。
 */

/*
 * 计算消息对象 input 按 schema 编码后的 TLV payload 字节数。
 * 成功时写入 encoded_size；不写码流，不分配内存。
 * schema、input 和 encoded_size 均须非 NULL。
 */
codec_status_t tlv_encode_size(const tlv_message_schema_t* schema,
    const void* input, size_t* encoded_size);

/*
 * 将消息对象 input 按 schema 编码到 buffer，buffer_size 为可写字节容量。
 * 空间足够时可直接调用，无需先测长；写入时逐次检查容量，不分配内存。
 * schema、input 和 buffer 均须非 NULL；written 可为 NULL。
 * written 非空时，成功写入实际字节数，失败置零；失败输出应丢弃。
 * 编码期间 input 必须保持不变，且不能与输出缓冲区重叠。
 * written 指向的存储不得与 schema、input 或输出缓冲区重叠。
 */
codec_status_t tlv_encode(const tlv_message_schema_t* schema,
    const void* input, uint8_t* buffer,
    size_t buffer_size, size_t* written);

/*
 * 将 input/input_size 指定的不含帧头的 TLV payload 按 schema 解码到消息对象 buffer。
 * schema、input 和 buffer 均须非 NULL；buffer_size 不得小于 schema->struct_size。
 * 不分配或初始化 buffer；调用方按用途初始化目标对象、数组 count 和 presence。
 * 未知 tag 跳过，缺失字段保留原值；非数组字段重复或 union 分支冲突时报错。
 * 失败时 buffer 可能已被部分修改，调用方应丢弃失败结果。
 */
codec_status_t tlv_decode(const tlv_message_schema_t* schema,
    const uint8_t* input, size_t input_size,
    void* buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
