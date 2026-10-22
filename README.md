# schema_TLV

基于 schema 的 TLV 编解码。

提供 C99 和 C++23 两版实现，内部不分配堆内存。

## Usage

定义消息结构体：

```cpp
#include "tlv.h"  // 这里以 C++ 版的头文件为例
#include <array>

struct message {
    uint32_t id;
    char name[128];
};
```

编写 schema 指定每个成员的 tag、类型和位置等信息：

```cpp
const tlv_field_schema_t fields[] = {
    {.tag = 1, .offset = offsetof(message, id), .type = TLV_VALUE_UINT32},
    {.tag = 2, .offset = offsetof(message, name), .type = TLV_VALUE_STRING, .string_capacity = 128}
};
const tlv_message_schema_t schema{sizeof(message), 2, fields};
```

然后传入结构体 + schema 进行编码；传入码流 + schema 进行解码：

```cpp
int main() {
    const message input{1, "client"}; // 待编码的结构体
    std::array<uint8_t, 256> buffer{}; // 存储编码后码流的 buffer

    auto written = tlv::encode(schema, input, buffer);
    if (!written) return 1;

    message output{};  // 接收解码结果的结构体/buffer，接口不会进行整体清零操作，按需进行初始化避免内存垃圾值，
    auto status = tlv::decode(schema, std::span(buffer).first(*written), output);
    if (!status) return 1;
}
```

更多示例见 [C demo](demo/c/demo.cpp)、[C++ demo](demo/cpp/demo_cpp.cpp)。

## 编解码约定

### 编码

- tag、length 和多字节整数字段均使用小端序。（我知道网络序一般指大端序）
- 每个单值字段或数组元素编码为 `[tag: uint16][length: uint32][value]`，length 只计 value 的字节数。
- 支持嵌套 message、字符串、数组、union、可选字段。
- 数组按 count 编码前 count 个元素，每个元素使用同一个 tag；空数组（count=0）不产生 TLV。解码每成功接收一个元素 tag 便递增 count，即解码后的 count 等于码流中本数组 tag 出现的次数。
- 字符串使用 `char[N]` 表示，包含结尾 \0。编码只取首个 \0 前的内容；解码拒绝 value 内含 \0，随后会在末尾补上 NUL。
- presence 是对象中的存在标记，配置后仅在标记置位时编码字段。
- union 按 choice 选择分支，若 choice 无一匹配则不编码。
- count、choice 和 presence 不会编码写入码流。

### 解码

解码遇到未知 tag 则跳过，继续解码。

除了数组类型外，对每个 tag 的处理总是独立的，因此如果遇到码流中存在重复的 tag，总是按照 schema 的描述对内存进行写入。

所以，对于重复 tag 的处理逻辑一般为，新值覆盖原内存值。

数组类型则是遇到重复 tag 则追加。
