#!/usr/bin/env python3
"""从零实现的 TCP 工具（仅标准库、不联网、不读写文件、不读时钟）。

子命令：
    python tcp.py segment encode   从标准输入读取 JSON，编码 TCP 报文段
    python tcp.py segment decode   从标准输入读取 JSON，解码并校验完整报文段

成功时向标准输出写入一个 JSON 对象；失败时标准输出为空，向标准错误
写入 {"error": ..., "message": ...}（固定键序）并以约定退出码退出：

    ParameterError       2   JSON 语法/字段缺失/参数非法/负载超限以外的输入问题
    SegmentFormatError   3   报文结构非法
    ChecksumError        4   校验和不匹配
    SegmentSizeError     5   负载超过最大负载长度
"""

import json
import struct
import sys

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_MAX_PAYLOAD = 1460

# 线格式上 FIN 为最低位（0x01），顺序向高至 CWR（0x80）；
# 输出与输入均按 FIN、SYN、RST、PSH、ACK、URG、ECE、CWR 排列。
FLAG_ORDER = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
FLAG_BITS = {name: 1 << i for i, name in enumerate(FLAG_ORDER)}
FLAG_NAMES = set(FLAG_ORDER)

OPT_EOL = 0
OPT_NOP = 1
OPT_MSS = 2

MIN_HEADER_LEN = 20
MAX_OPTIONS_LEN = 40

TCP_PROTOCOL = 6

_ERROR_SPECS = {
    "ParameterError": 2,
    "SegmentFormatError": 3,
    "ChecksumError": 4,
    "SegmentSizeError": 5,
}


class TcpError(Exception):
    """所有可预期输入错误的基类，子类名即 JSON 中的 error 值。"""


class ParameterError(TcpError):
    pass


class SegmentFormatError(TcpError):
    pass


class ChecksumError(TcpError):
    pass


class SegmentSizeError(TcpError):
    pass


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------

def _require_object(value, name):
    if not isinstance(value, dict):
        raise ParameterError("%s must be an object" % name)
    return value


def _require_list(value, name):
    if not isinstance(value, list):
        raise ParameterError("%s must be a list" % name)
    return value


def _require_str(value, name):
    if not isinstance(value, str):
        raise ParameterError("%s must be a string" % name)
    return value


def _require_int(value, name, minimum, maximum):
    """闭区间整数；bool 与越界值一律拒绝。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParameterError("%s must be an integer" % name)
    if value < minimum or value > maximum:
        raise ParameterError(
            "%s out of range (%d..%d)" % (name, minimum, maximum))
    return value


def _field(obj, name, where):
    if name not in obj:
        raise ParameterError("%s missing key: %s" % (where, name))
    return obj[name]


def parse_ipv4(text):
    """只接受规范四段点分十进制，返回 4 字节 bytes。"""
    s = _require_str(text, "IPv4 address")
    parts = s.split(".")
    if len(parts) != 4:
        raise ParameterError("invalid IPv4 address: %r" % s)
    out = bytearray(4)
    for i, part in enumerate(parts):
        # 仅 ASCII 数字：拒绝空段、符号、空白、unicode 数字、前导零。
        if (not part
                or not all("0" <= c <= "9" for c in part)
                or len(part) > 3
                or (len(part) > 1 and part[0] == "0")):
            raise ParameterError("invalid IPv4 address: %r" % s)
        value = int(part)
        if value > 255:
            raise ParameterError("invalid IPv4 address: %r" % s)
        out[i] = value
    return bytes(out)


def parse_hex(text, name, *, allow_empty=True):
    s = _require_str(text, name)
    if s == "":
        if not allow_empty:
            raise ParameterError("%s must not be empty" % name)
        return b""
    if len(s) % 2 != 0:
        raise ParameterError("%s must have even hex length" % name)
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ParameterError("%s is not valid hexadecimal" % name)


def parse_flags(value):
    """标志为八个已知名字构成的无重复数组，返回字节位掩码。"""
    items = _require_list(value, "flags")
    mask = 0
    seen = set()
    for item in items:
        if not isinstance(item, str):
            raise ParameterError("each flag must be a string")
        if item not in FLAG_NAMES:
            raise ParameterError("unknown flag: %s" % item)
        if item in seen:
            raise ParameterError("duplicate flag: %s" % item)
        seen.add(item)
        mask |= FLAG_BITS[item]
    return mask


# ---------------------------------------------------------------------------
# 选项
#
# 规范形式：选项按序序列化，末尾用 0x00 补齐到 4 字节边界（第一个补的
# 0x00 即 EOL，其余零字节是 EOL 之后的填充）。EOL/NOP 在 decode 时
# 原样保留在选项列表中，从而保证 decode -> encode 逐字节一致。
# ---------------------------------------------------------------------------

def encode_options(options):
    items = _require_list(options, "options")
    raw = bytearray()
    for index, opt in enumerate(items):
        where = "options[%d]" % index
        _require_object(opt, where)
        keys = set(opt.keys())
        if "type" not in keys:
            raise ParameterError("%s missing key: type" % where)
        kind = _require_int(opt["type"], where + ".type", 0, 255)

        if kind == OPT_EOL:
            if keys != {"type"}:
                raise ParameterError(
                    "%s: EOL option takes no extra keys" % where)
            if index != len(items) - 1:
                raise ParameterError(
                    "%s: EOL must be the final option" % where)
            raw.append(OPT_EOL)
        elif kind == OPT_NOP:
            if keys != {"type"}:
                raise ParameterError(
                    "%s: NOP option takes no extra keys" % where)
            raw.append(OPT_NOP)
        elif kind == OPT_MSS:
            if keys != {"type", "mss"}:
                raise ParameterError(
                    "%s: MSS option requires exactly type and mss" % where)
            mss = _require_int(opt["mss"], where + ".mss", 1, 65535)
            raw += bytes((OPT_MSS, 4)) + struct.pack("!H", mss)
        else:
            if keys != {"type", "length", "data"}:
                raise ParameterError(
                    "%s: unknown option requires type, length and data"
                    % where)
            length = _require_int(opt["length"], where + ".length", 2, 255)
            data = parse_hex(opt["data"], where + ".data")
            if len(data) != length - 2:
                raise ParameterError(
                    "%s: data length does not match option length" % where)
            raw.append(kind)
            raw.append(length)
            raw += data

    if len(raw) > MAX_OPTIONS_LEN:
        raise ParameterError(
            "options do not fit in TCP header (%d bytes max)"
            % MAX_OPTIONS_LEN)
    pad = (-len(raw)) % 4
    if len(raw) + pad > MAX_OPTIONS_LEN:
        raise ParameterError(
            "options do not fit in TCP header (%d bytes max)"
            % MAX_OPTIONS_LEN)
    raw.extend(b"\x00" * pad)
    return bytes(raw)


def decode_options(blob):
    """解析选项区；任何结构问题抛 SegmentFormatError。"""
    options = []
    i = 0
    n = len(blob)
    while i < n:
        kind = blob[i]
        if kind == OPT_EOL:
            # EOL 保留在规范化结果中；其后只允许零填充。
            options.append({"type": OPT_EOL})
            tail = blob[i + 1:]
            if any(b != 0 for b in tail):
                raise SegmentFormatError(
                    "non-zero padding byte after End of Option List")
            return options
        if kind == OPT_NOP:
            options.append({"type": OPT_NOP})
            i += 1
            continue

        if i + 1 >= n:
            raise SegmentFormatError("truncated TCP option (missing length)")
        length = blob[i + 1]
        if length < 2:
            raise SegmentFormatError("TCP option length must be >= 2")
        if i + length > n:
            raise SegmentFormatError("TCP option extends past header")
        data = blob[i + 2:i + length]
        if kind == OPT_MSS:
            if length != 4:
                raise SegmentFormatError("MSS option must have length 4")
            mss = struct.unpack("!H", data)[0]
            if mss < 1:
                raise SegmentFormatError("MSS must be in 1..65535")
            options.append({"type": OPT_MSS, "mss": mss})
        else:
            # 未知选项：类型、长度、原始数据原样返回。
            options.append({
                "type": kind,
                "length": length,
                "data": bytes(data).hex(),
            })
        i += length
    return options


# ---------------------------------------------------------------------------
# 校验和：IPv4 伪首部 + TCP 头（校验和字段置零）+ 负载
# ---------------------------------------------------------------------------

def checksum(data):
    """16 位反码和；奇数个尾字节仅在计算时补一个零字节。"""
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pseudo_header(src_ip, dst_ip, tcp_length):
    return (src_ip
            + dst_ip
            + struct.pack("!BBH", 0, TCP_PROTOCOL, tcp_length))


# ---------------------------------------------------------------------------
# segment encode
# ---------------------------------------------------------------------------

def cmd_encode(obj):
    _require_object(obj, "input")

    src_ip = parse_ipv4(_field(obj, "source_ip", "input"))
    dst_ip = parse_ipv4(_field(obj, "destination_ip", "input"))
    src_port = _require_int(_field(obj, "source_port", "input"),
                            "source_port", 0, 65535)
    dst_port = _require_int(_field(obj, "destination_port", "input"),
                            "destination_port", 0, 65535)
    seq = _require_int(_field(obj, "sequence_number", "input"),
                       "sequence_number", 0, 0xFFFFFFFF)
    ack = _require_int(obj.get("acknowledgment_number", 0),
                       "acknowledgment_number", 0, 0xFFFFFFFF)
    flags = parse_flags(_field(obj, "flags", "input"))
    window = _require_int(obj.get("window", 0), "window", 0, 65535)
    urgent = _require_int(obj.get("urgent_pointer", 0),
                          "urgent_pointer", 0, 65535)
    options = encode_options(obj.get("options", []))
    payload = parse_hex(obj.get("payload", ""), "payload")
    max_payload = _require_int(
        obj.get("maximum_payload_length", DEFAULT_MAX_PAYLOAD),
        "maximum_payload_length", 0, 0xFFFFFFFF)

    # 负载超限只报错，绝不截断。
    if len(payload) > max_payload:
        raise SegmentSizeError(
            "payload length %d exceeds maximum payload length %d"
            % (len(payload), max_payload))

    header_length = MIN_HEADER_LEN + len(options)
    if header_length + len(payload) > 0xFFFF:
        raise SegmentSizeError(
            "segment length exceeds 65535 bytes (TCP length field limit)")
    data_offset = header_length // 4  # 选项已按 4 字节补齐
    header = bytearray(struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (data_offset << 4),
        flags,
        window,
        0,  # 校验和字段计算时置零
        urgent,
    ))
    header += options

    pseudo = pseudo_header(src_ip, dst_ip, header_length + len(payload))
    csum = checksum(pseudo + bytes(header) + payload)
    struct.pack_into("!H", header, 16, csum)

    return {
        "operation": "segment encode",
        "segment_hex": (bytes(header) + payload).hex(),
        "header_length": header_length,
        "payload_length": len(payload),
        "checksum": csum,
    }


# ---------------------------------------------------------------------------
# segment decode
# ---------------------------------------------------------------------------

def cmd_decode(obj):
    _require_object(obj, "input")

    ctx = _field(obj, "addresses", "input")
    _require_object(ctx, "addresses")
    src_ip = parse_ipv4(_field(ctx, "source_ip", "addresses"))
    dst_ip = parse_ipv4(_field(ctx, "destination_ip", "addresses"))

    segment = parse_hex(_field(obj, "segment", "input"),
                        "segment", allow_empty=False)

    # 1) 最小头部
    if len(segment) < MIN_HEADER_LEN:
        raise SegmentFormatError(
            "segment shorter than minimum TCP header (20 bytes)")

    (src_port, dst_port, seq, ack, offset_byte, flags,
     window, stored_csum, urgent) = struct.unpack(
        "!HHIIBBHHH", segment[:MIN_HEADER_LEN])

    # 2) 数据偏移（含保留位/NS 位）
    data_offset = offset_byte >> 4
    if offset_byte & 0x0F:
        raise SegmentFormatError(
            "reserved/NS bits in data offset byte must be zero")
    header_length = data_offset * 4
    if header_length < MIN_HEADER_LEN:
        raise SegmentFormatError("data offset below minimum (5)")
    if header_length > len(segment):
        raise SegmentFormatError("data offset extends past end of segment")

    # 3) 选项长度与结构
    options = decode_options(segment[MIN_HEADER_LEN:header_length])
    payload = segment[header_length:]

    # 4) 校验和（校验时校验和字段置零）
    zeroed = bytearray(segment)
    struct.pack_into("!H", zeroed, 16, 0)
    pseudo = pseudo_header(src_ip, dst_ip, len(segment))
    if checksum(pseudo + bytes(zeroed)) != stored_csum:
        raise ChecksumError("TCP checksum mismatch")

    flag_names = [name for name in FLAG_ORDER if flags & FLAG_BITS[name]]

    return {
        "source_ip": ".".join(str(b) for b in src_ip),
        "destination_ip": ".".join(str(b) for b in dst_ip),
        "source_port": src_port,
        "destination_port": dst_port,
        "sequence_number": seq,
        "acknowledgment_number": ack,
        "flags": flag_names,
        "window": window,
        "urgent_pointer": urgent,
        "options": options,
        "payload": payload.hex(),
        "segment_length": len(segment),
        "header_length": header_length,
        "checksum": stored_csum,
    }


# ---------------------------------------------------------------------------
# 总入口
# ---------------------------------------------------------------------------

def _write_stderr_json(obj):
    sys.stderr.write(
        json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")


def _fail(error, message):
    sys.stdout.flush()
    _write_stderr_json({"error": error, "message": message})
    sys.stderr.flush()
    return _ERROR_SPECS[error]


def main(argv):
    if (len(argv) != 3
            or argv[1] != "segment"
            or argv[2] not in ("encode", "decode")):
        return _fail("ParameterError",
                     "usage: python tcp.py segment {encode|decode}")

    try:
        raw_text = sys.stdin.buffer.read().decode("utf-8")
    except UnicodeDecodeError:
        return _fail("ParameterError",
                     "standard input must be UTF-8 encoded JSON")
    try:
        obj = json.loads(raw_text)
    except json.JSONDecodeError:
        return _fail("ParameterError",
                     "standard input must be one valid JSON object")
    if not isinstance(obj, dict):
        return _fail("ParameterError",
                     "top-level JSON value must be an object")

    handler = cmd_encode if argv[2] == "encode" else cmd_decode
    try:
        result = handler(obj)
    except TcpError as exc:
        return _fail(type(exc).__name__, str(exc))

    sys.stdout.write(
        json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
