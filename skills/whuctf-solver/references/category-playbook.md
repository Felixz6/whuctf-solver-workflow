# 分类战术：按问题而不是按工具推进

## 1. Reverse（最高备战优先级）
`file/xxd/strings` → LIEF/ELF/PE结构 → radare2函数与xref → 输入到比较的控制/数据流 → 恢复算法 → 写求解器 → 回送校验。无关函数和全部反汇编不必倾倒到上下文。

- 先记录真实格式、CPU、位数、端序、是否PIE/壳、入口、导入和资源。异常处理、TLS回调、线程、JNI、GPU代码可隐藏有效路径。
- 区分 `transform(input)==target` 与 `transform(target)==input`。TEA/XTEA/XXTEA看更新式和轮次，不能只看到delta就套算法。逐操作截断和带符号比较按目标CPU语义。
- VM：取指单位、指令长度、操作数、PC推进、栈方向、寄存器/内存别名、溢出/异常；恢复opcode表后trace，不能直接把字节当本机机器码。
- Z3：8/32/64-bit BitVec；逻辑右移用LShR；带符号/无符号关系显式选择；检查模型唯一性或验证全部候选；设置超时以便反查约束。
- Unicorn：仅模拟已识别函数/代码段，正确映射栈、数据、返回地址、调用约定；导入调用显式hook。是CPU模拟，不自动提供操作系统syscall语义。
- angr：先给真实输入长度/格式约束，识别find/avoid地址，处理PIE的rebased_addr；禁把未约束填零/任意hook当作解题证明；模型必须回送真实逻辑。
- Android：DEX与JNI两条线一起追；RegisterNatives、资源、签名/设备信息、Java字符串和native缓冲区转换要贯通。Python pyc匹配字节码版本；WASM查导出、线性内存与字符串编码。

## 2. Web
请求/响应基线 → 路由和源代码 → 数据流/信任边界 → 最小漏洞原语 → flag链。优先实际题目中的差分面；自定义cookie/JWT、模板、文件接口、URL解析、上传/解压、反序列化、原型链与bot调用各找对应入口。
保留正常与payload的原始请求、响应、状态码及关键字段。CVE必须与真实版本及触发条件匹配；库名命中不等于漏洞成立。平台功能与题目实例分开记录。

## 3. Crypto
先归类参数与可查询oracle；RSA检测gcd/小e/共模/近素数/相关消息/泄漏；对称算法检测IV/nonce复用、模式和认证；随机数区分Python/C/V8实现。
HNP/小误差/部分泄漏才构造格；写出模方程、未知量界、basis每行、尺度、解向量意义并代入验证。fpylll不替代所有Sage有限域/代数功能。

## 4. Pwn
ELF/ABI与安全保护 → 漏洞与输入约束 → 可重复原语 → 泄漏和地址 → exploit。远程libc和ld以附件为准，不用本机版本猜。现代glibc与safe-linking、hook移除、FILE/vtable检查必须匹配版本；不给通用旧heap技巧冒充当前解。
在与题目一致的平台验证进程调试、seccomp、ptrace 和 libc 行为；主机上的静态分析或 payload 生成不能替代目标环境运行验证。

## 5. Misc与其他
按magic而非后缀识别压缩包/图片/PCAP/音频；先元数据、结构和显著异常，再选择字符编码、LSB/通道、数据流、频谱等路线。解压保留原包，检查路径；jail源码逐行追约束，区分语言语义与额外黑名单。
PCAP优先按协议/会话重组后取应用数据；图片/音频保留每层产物与提取参数。需要forensics、OSINT或AI/ML专题时加载其现有技能。
