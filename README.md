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

### 码流与编码

- 按小端序进行编解码。（我知道网络序一般指大端序）
- 每个字段编码为 `[tag: uint16][length: uint32][value]`。
- 支持嵌套 message、字符串、数组、union、可选字段。
- 数组的 count 不编码，码流中没有 count，解码时根据不数组元素 tag 出现次数写入 count。
- 字符串为 char[N] 表示，容量 N 包含结尾 \0；编码时只编入首个 \0 前的字符，码流不含 \0。解码拒绝字符串中存在 \0
- 配置了 presence 的字段只在存在时编码；
- union 按 choice 选择分支，若 choice 无一匹配则不编码。

### 解码与重复 tag

解码遇到未知 tag 则跳过，继续解码。

除了数组类型外，对每个 tag 的总是独立的，因此如果遇到码流中存在重复的 tag，总是按照 schema 的描述写入。
所以，对于重复 tag 的处理逻辑为，新值覆盖旧值。
数组类型则是遇到重复 tag 则追加。
