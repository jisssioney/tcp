#!/usr/bin/env python3
"""TCP/IPv4 报文段编解码工具（仅用标准库，确定性输出）。

入口：
    python tcp.py segment encode   从标准输入 JSON 编码一个 TCP 报文段
    python tcp.py segment decode   从标准输入 JSON 解码并校验完整报文段

两次调用都从标准输入读取一个 UTF-8 JSON 对象，成功时向标准输出写一行
紧凑 JSON（固定键序、十六进制小写）。失败时标准输出为空，向标准错误
写一行 {"error": ..., "message": ...}（固定键序），退出码：

    ParameterError       2   JSON 语法错误、字段缺失或参数非法
    SegmentFormatError   3   报文段结构非法
    ChecksumError        4   校验和不匹配
    SegmentSizeError     5   负载超过最大负载长度

不联网、不读写文件、不读取墙上时钟；相同输入逐字节一致。
"""

import json
import struct
import sys

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_MAX_PAYLOAD_LENGTH = 1460

PORT_MIN, PORT_MAX = 0, 0xFFFF
SEQ_MIN, SEQ_MAX = 0, 0xFFFFFFFF
WINDOW_MIN, WINDOW_MAX = 0, 0xFFFF
URGENT_MIN, URGENT_MAX = 0, 0xFFFF

TCP_HEADER_MIN = 20          # 不含选项的最小头部长度
TCP_OPTIONS_MAX = 40         # 选项区上限
TCP_SEGMENT_MAX = 0xFFFF     # IPv4 总长字段给 TCP 段的上限
IP_PROTOCOL_TCP = 6

OPT_EOL = 0                  # End of Option List
OPT_NOP = 1                  # No-Operation
OPT_MSS = 2                  # Maximum Segment Size

# 线格式上 FIN 位于最低位（0x01），依次向高至 CWR（0x80）。
# 输入与输出统一按 FIN、SYN、RST、PSH、ACK、URG、ECE、CWR 排列。
FLAG_ORDER = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
FLAG_BITS = {name: 1 << index for index, name in enumerate(FLAG_ORDER)}
FLAG_KNOWN = frozenset(FLAG_ORDER)

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

_ERROR_EXIT_CODES = {
    "ParameterError": 2,
    "SegmentFormatError": 3,
    "ChecksumError": 4,
    "SegmentSizeError": 5,
}


class TcpError(Exception):
    """可预期输入错误的基类；子类名即错误 envelope 的 error 值。"""


class ParameterError(TcpError):
    """JSON 语法错误、字段缺失或参数非法（退出码 2）。"""


class SegmentFormatError(TcpError):
    """报文段结构非法（退出码 3）。"""


class ChecksumError(TcpError):
    """校验和不匹配（退出码 4）。"""


class SegmentSizeError(TcpError):
    """负载超过最大负载长度（退出码 5）。"""


# ---------------------------------------------------------------------------
# 基础类型校验
# ---------------------------------------------------------------------------

def _require_object(value, where):
    if not isinstance(value, dict):
        raise ParameterError("%s 必须是 JSON 对象" % where)
    return value


def _require_list(value, where):
    if not isinstance(value, list):
        raise ParameterError("%s 必须是数组" % where)
    return value


def _require_int(value, where, low, high):
    """闭区间整数；bool 是 int 的子类，必须显式拒绝。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParameterError("%s 必须是 %d..%d 的整数" % (where, low, high))
    if not low <= value <= high:
        raise ParameterError("%s 超出范围 %d..%d" % (where, low, high))
    return value


def _field(obj, name, where):
    if name not in obj:
        raise ParameterError("%s 缺少字段: %s" % (where, name))
    return obj[name]


def parse_ipv4(value, where):
    """只接受规范四段点分十进制，返回 4 字节 bytes。"""
    if not isinstance(value, str):
        raise ParameterError("%s 必须是 IPv4 地址字符串" % where)
    parts = value.split(".")
    if len(parts) != 4:
        raise ParameterError("%s 不是合法 IPv4 地址: %r" % (where, value))
    result = bytearray(4)
    for index, part in enumerate(parts):
        # 只接受 ASCII 十进制数字：拒绝空段、符号、空白、unicode 数字与前导零。
        if (not part
                or any(ch < "0" or ch > "9" for ch in part)
                or len(part) > 3
                or (len(part) > 1 and part[0] == "0")):
            raise ParameterError(
                "%s 不是规范四段十进制 IPv4 地址: %r" % (where, value))
        octet = int(part)
        if octet > 255:
            raise ParameterError(
                "%s 不是合法 IPv4 地址: %r" % (where, value))
        result[index] = octet
    return bytes(result)


def parse_hex(value, where, *, allow_empty=True):
    """偶数长度、仅十六进制字符的字符串；返回原始字节。"""
    if not isinstance(value, str):
        raise ParameterError("%s 必须是十六进制字符串" % where)
    if len(value) == 0:
        if not allow_empty:
            raise ParameterError("%s 不能为空" % where)
        return b""
    if len(value) % 2 != 0:
        raise ParameterError("%s 十六进制长度必须为偶数" % where)
    if any(ch not in _HEX_DIGITS for ch in value):
        raise ParameterError("%s 含有非十六进制字符" % where)
    return bytes.fromhex(value)


def parse_flags(value):
    """标志为已知名字构成的无重复数组（顺序不做要求），返回线格式位掩码。"""
    items = _require_list(value, "flags")
    mask = 0
    seen = set()
    for item in items:
        if not isinstance(item, str):
            raise ParameterError("flags 数组元素必须是字符串")
        if item not in FLAG_KNOWN:
            raise ParameterError("未知标志: %s" % item)
        if item in seen:
            raise ParameterError("重复标志: %s" % item)
        seen.add(item)
        mask |= FLAG_BITS[item]
    return mask


# ---------------------------------------------------------------------------
# 选项
#
# 选项区布局：选项按序排列，末尾以 0x00 补齐到 4 字节边界（首个补齐字节
# 即 EOL，其余为对齐填充）。decode 保留 NOP/EOL 与未知选项原样，保证
# 合法报文 decode 后再 encode 逐字节一致。
# ---------------------------------------------------------------------------

def encode_options(value):
    """把规范选项数组编码为线上选项区（含四字节对齐零填充）。"""
    items = _require_list(value, "options")
    raw = bytearray()
    for index, option in enumerate(items):
        where = "options[%d]" % index
        _require_object(option, where)
        keys = set(option.keys())
        if "type" not in keys:
            raise ParameterError("%s 缺少字段: type" % where)
        kind = _require_int(option["type"], where + ".type", 0, 255)

        if kind == OPT_EOL:
            if keys != {"type"}:
                raise ParameterError("%s: EOL 不接受额外字段" % where)
            if index != len(items) - 1:
                raise ParameterError("%s: EOL 必须是最后一个选项" % where)
            raw.append(OPT_EOL)
        elif kind == OPT_NOP:
            if keys != {"type"}:
                raise ParameterError("%s: NOP 不接受额外字段" % where)
            raw.append(OPT_NOP)
        elif kind == OPT_MSS:
            if keys != {"type", "mss"}:
                raise ParameterError(
                    "%s: MSS 选项必须恰好包含 type 与 mss" % where)
            mss = _require_int(option["mss"], where + ".mss", 1, 0xFFFF)
            raw += bytes((OPT_MSS, 4)) + struct.pack("!H", mss)
        else:
            # 未知选项原样保留：type、length 与原始数据。
            if keys != {"type", "length", "data"}:
                raise ParameterError(
                    "%s: 未知选项必须包含 type、length、data" % where)
            length = _require_int(
                option["length"], where + ".length", 2, 255)
            data = parse_hex(option["data"], where + ".data")
            if len(data) != length - 2:
                raise ParameterError(
                    "%s: data 长度与选项 length 不一致" % where)
            raw.append(kind)
            raw.append(length)
            raw += data

    if len(raw) > TCP_OPTIONS_MAX:
        raise ParameterError("选项区超过 %d 字节" % TCP_OPTIONS_MAX)
    padding = (-len(raw)) % 4
    if len(raw) + padding > TCP_OPTIONS_MAX:
        raise ParameterError("选项区补齐后超过 %d 字节" % TCP_OPTIONS_MAX)
    raw += b"\x00" * padding
    return bytes(raw)


def decode_options(area):
    """解析数据偏移指示的完整选项区；结构问题一律抛 SegmentFormatError。"""
    options = []
    index = 0
    total = len(area)
    while index < total:
        kind = area[index]
        if kind == OPT_EOL:
            options.append({"type": OPT_EOL})
            # EOL 之后只允许对齐用的零字节。
            if any(byte != 0 for byte in area[index + 1:]):
                raise SegmentFormatError("EOL 之后存在非零填充字节")
            return options
        if kind == OPT_NOP:
            options.append({"type": OPT_NOP})
            index += 1
            continue

        # 其余选项统一为 kind(1) + length(1) + data(length-2)。
        if index + 1 >= total:
            raise SegmentFormatError("选项缺少 length 字节")
        length = area[index + 1]
        if length < 2:
            raise SegmentFormatError("选项 length 必须不小于 2")
        if index + length > total:
            raise SegmentFormatError("选项超出选项区边界")
        data = area[index + 2:index + length]
        if kind == OPT_MSS:
            if length != 4:
                raise SegmentFormatError("MSS 选项 length 必须为 4")
            mss = struct.unpack("!H", data)[0]
            if mss < 1:
                raise SegmentFormatError("MSS 取值必须在 1..65535")
            options.append({"type": OPT_MSS, "mss": mss})
        else:
            options.append({
                "type": kind,
                "length": length,
                "data": bytes(data).hex(),
            })
        index += length
    return options


# ---------------------------------------------------------------------------
# Internet 校验和：IPv4 伪首部 + TCP 头（校验和字段置零）+ 负载
# ---------------------------------------------------------------------------

def internet_checksum(data):
    """16 位反码和；奇数个尾字节只在计算中补一个零字节。"""
    padded = data + b"\x00" if len(data) % 2 else data
    total = 0
    for index in range(0, len(padded), 2):
        total += (padded[index] << 8) | padded[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# 简短别名，便于直接以 tcp.checksum 复用校验和原语。
checksum = internet_checksum


def pseudo_header(src_ip, dst_ip, tcp_length):
    return (src_ip
            + dst_ip
            + struct.pack("!BBH", 0, IP_PROTOCOL_TCP, tcp_length))


# ---------------------------------------------------------------------------
# segment encode
# ---------------------------------------------------------------------------

def command_encode(obj):
    _require_object(obj, "输入")

    src_ip = parse_ipv4(_field(obj, "source_ip", "输入"), "source_ip")
    dst_ip = parse_ipv4(
        _field(obj, "destination_ip", "输入"), "destination_ip")
    src_port = _require_int(
        _field(obj, "source_port", "输入"), "source_port", PORT_MIN, PORT_MAX)
    dst_port = _require_int(
        _field(obj, "destination_port", "输入"),
        "destination_port", PORT_MIN, PORT_MAX)
    sequence_number = _require_int(
        _field(obj, "sequence_number", "输入"),
        "sequence_number", SEQ_MIN, SEQ_MAX)
    acknowledgment_number = _require_int(
        obj.get("acknowledgment_number", 0),
        "acknowledgment_number", SEQ_MIN, SEQ_MAX)
    flags = parse_flags(_field(obj, "flags", "输入"))
    window = _require_int(
        obj.get("window", 0), "window", WINDOW_MIN, WINDOW_MAX)
    urgent_pointer = _require_int(
        obj.get("urgent_pointer", 0), "urgent_pointer",
        URGENT_MIN, URGENT_MAX)
    options = encode_options(obj.get("options", []))
    payload = parse_hex(obj.get("payload", ""), "payload")
    maximum_payload_length = _require_int(
        obj.get("maximum_payload_length", DEFAULT_MAX_PAYLOAD_LENGTH),
        "maximum_payload_length", 0, SEQ_MAX)

    # 负载超限直接失败，绝不截断。
    if len(payload) > maximum_payload_length:
        raise SegmentSizeError(
            "负载长度 %d 超过最大负载长度 %d"
            % (len(payload), maximum_payload_length))

    header_length = TCP_HEADER_MIN + len(options)
    if header_length + len(payload) > TCP_SEGMENT_MAX:
        raise SegmentSizeError(
            "报文段总长超过 IPv4 承载上限 %d 字节" % TCP_SEGMENT_MAX)

    data_offset = header_length // 4  # 选项区已补齐到四字节边界
    header = bytearray(struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        sequence_number,
        acknowledgment_number,
        data_offset << 4,
        flags,
        window,
        0,  # 计算校验和时该字段置零
        urgent_pointer,
    ))
    header += options

    checksum = internet_checksum(
        pseudo_header(src_ip, dst_ip, header_length + len(payload))
        + bytes(header)
        + payload)
    struct.pack_into("!H", header, 16, checksum)

    return {
        "operation": "segment encode",
        "segment_hex": (bytes(header) + payload).hex(),
        "header_length": header_length,
        "payload_length": len(payload),
        "checksum": checksum,
    }


# ---------------------------------------------------------------------------
# segment decode
# ---------------------------------------------------------------------------

def command_decode(obj):
    _require_object(obj, "输入")

    addresses = _field(obj, "addresses", "输入")
    _require_object(addresses, "addresses")
    src_ip = parse_ipv4(
        _field(addresses, "source_ip", "addresses"), "source_ip")
    dst_ip = parse_ipv4(
        _field(addresses, "destination_ip", "addresses"), "destination_ip")

    segment = parse_hex(
        _field(obj, "segment", "输入"), "segment", allow_empty=False)

    # 1) 最小头部长度与 IPv4 承载上限（伪首部长度字段为 16 位）。
    if len(segment) < TCP_HEADER_MIN:
        raise SegmentFormatError("报文段短于最小 TCP 头部 20 字节")
    if len(segment) > TCP_SEGMENT_MAX:
        raise SegmentFormatError("报文段超过 IPv4 承载上限 65535 字节")

    (src_port, dst_port, sequence_number, acknowledgment_number,
     offset_byte, flags_byte, window, stored_checksum,
     urgent_pointer) = struct.unpack(
        "!HHIIBBHHH", segment[:TCP_HEADER_MIN])

    # 2) 数据偏移与保留位（含 NS 位）：低四位必须为零。
    if offset_byte & 0x0F:
        raise SegmentFormatError("数据偏移字节的保留位必须为零")
    data_offset = offset_byte >> 4
    header_length = data_offset * 4
    if header_length < TCP_HEADER_MIN:
        raise SegmentFormatError("数据偏移小于最小值 5")
    if header_length > len(segment):
        raise SegmentFormatError("数据偏移超出报文段末尾")

    # 3) 选项长度与结构。
    options = decode_options(
        segment[TCP_HEADER_MIN:header_length])
    payload = segment[header_length:]

    # 4) 校验和：计算时校验和字段置零，结果应与线上字段一致。
    zeroed = bytearray(segment)
    struct.pack_into("!H", zeroed, 16, 0)
    calculated = internet_checksum(
        pseudo_header(src_ip, dst_ip, len(segment)) + bytes(zeroed))
    if calculated != stored_checksum:
        raise ChecksumError("TCP 校验和不匹配")

    flag_names = [
        name for name in FLAG_ORDER if flags_byte & FLAG_BITS[name]
    ]

    # 按 TCP 字段顺序输出；地址经规范化后重新写出。
    return {
        "source_ip": ".".join(str(octet) for octet in src_ip),
        "destination_ip": ".".join(str(octet) for octet in dst_ip),
        "source_port": src_port,
        "destination_port": dst_port,
        "sequence_number": sequence_number,
        "acknowledgment_number": acknowledgment_number,
        "flags": flag_names,
        "window": window,
        "urgent_pointer": urgent_pointer,
        "options": options,
        "payload": payload.hex(),
        "segment_length": len(segment),
        "header_length": header_length,
        "checksum": stored_checksum,
    }


# ---------------------------------------------------------------------------
# 总入口
# ---------------------------------------------------------------------------

def _emit_error(name, message):
    # 任何失败路径都不得在标准输出留下内容。
    sys.stdout.flush()
    sys.stderr.write(json.dumps(
        {"error": name, "message": message},
        ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stderr.flush()


def main(argv):
    if (len(argv) != 3
            or argv[1] != "segment"
            or argv[2] not in ("encode", "decode")):
        _emit_error(
            "ParameterError", "用法: python tcp.py segment {encode|decode}")
        return _ERROR_EXIT_CODES["ParameterError"]

    try:
        raw_text = sys.stdin.buffer.read().decode("utf-8")
    except UnicodeDecodeError:
        _emit_error("ParameterError", "标准输入必须是 UTF-8 编码")
        return _ERROR_EXIT_CODES["ParameterError"]
    try:
        obj = json.loads(raw_text)
    except json.JSONDecodeError:
        _emit_error("ParameterError", "标准输入必须是一个合法 JSON 对象")
        return _ERROR_EXIT_CODES["ParameterError"]
    if not isinstance(obj, dict):
        _emit_error("ParameterError", "顶层 JSON 值必须是对象")
        return _ERROR_EXIT_CODES["ParameterError"]

    handler = command_encode if argv[2] == "encode" else command_decode
    try:
        result = handler(obj)
    except TcpError as exc:
        name = type(exc).__name__
        _emit_error(name, str(exc))
        return _ERROR_EXIT_CODES[name]

    sys.stdout.write(json.dumps(
        result, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
