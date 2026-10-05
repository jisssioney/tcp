"""tcp.py segment encode/decode 的单元测试（仅标准库）。

运行：python -m unittest discover
"""

import json
import struct
import subprocess
import sys
import unittest

import tcp

PYTHON = sys.executable


# ---------------------------------------------------------------------------
# 独立参考实现，用于交叉校验
# ---------------------------------------------------------------------------

def ref_checksum(data):
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ref_pseudo(src, dst, tcp_length):
    return (bytes(int(x) for x in src.split("."))
            + bytes(int(x) for x in dst.split("."))
            + struct.pack("!BBH", 0, 6, tcp_length))


FLAG_MASK = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
    "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}


def run_cli(subcommand, payload_obj=None, *, raw=None):
    """以子进程方式运行 CLI，返回 (returncode, stdout_bytes, stderr_bytes)。"""
    if raw is None:
        raw = json.dumps(payload_obj).encode("utf-8")
    proc = subprocess.run(
        [PYTHON, "tcp.py", "segment", subcommand],
        input=raw, capture_output=True)
    return proc.returncode, proc.stdout, proc.stderr


def encode_obj(**overrides):
    obj = {
        "source_ip": "192.168.0.1",
        "destination_ip": "10.0.0.1",
        "source_port": 1234,
        "destination_port": 4321,
        "sequence_number": 0,
        "flags": [],
    }
    obj.update(overrides)
    return obj


def encode(**overrides):
    rc, out, err = run_cli("encode", encode_obj(**overrides))
    assert rc == 0, err.decode()
    return json.loads(out)


def decode_obj(segment_hex, src="192.168.0.1", dst="10.0.0.1"):
    return {
        "addresses": {"source_ip": src, "destination_ip": dst},
        "segment": segment_hex,
    }


def decode(segment_hex, src="192.168.0.1", dst="10.0.0.1"):
    rc, out, err = run_cli(
        "decode", decode_obj(segment_hex, src, dst))
    assert rc == 0, err.decode()
    return json.loads(out)


class ChecksumTests(unittest.TestCase):
    def test_known_syn_vector(self):
        # RFC 风格的手工 SYN 报文（零校验和字段），期望校验和 0xcf85。
        segment = bytes.fromhex(
            "04d210e100000000000000005002ffff00000000")
        pseudo = ref_pseudo("192.168.0.1", "10.0.0.1", len(segment))
        self.assertEqual(ref_checksum(pseudo + segment), 0xcf85)
        self.assertEqual(tcp.checksum(pseudo + segment), 0xcf85)

    def test_odd_length_zero_pad_only_in_computation(self):
        # 奇数长度时尾字节按高 8 位补零参与计算。
        self.assertEqual(tcp.checksum(b"\x01"),
                         ref_checksum(b"\x01"))
        self.assertEqual(tcp.checksum(b"\x01\x00\x02"),
                         ref_checksum(b"\x01\x00\x02"))


class EncodeTests(unittest.TestCase):
    def test_known_syn_bytes(self):
        result = encode(flags=["SYN"], window=65535)
        self.assertEqual(
            result["segment_hex"],
            "04d210e100000000000000005002ffffcf850000")
        self.assertEqual(result["header_length"], 20)
        self.assertEqual(result["payload_length"], 0)
        self.assertEqual(result["checksum"], 0xcf85)

    def test_output_key_order_fixed(self):
        rc, out, err = run_cli("encode", encode_obj(flags=["FIN"]))
        self.assertEqual(rc, 0)
        keys = list(json.loads(out.decode()).keys())
        self.assertEqual(
            keys,
            ["operation", "segment_hex", "header_length",
             "payload_length", "checksum"])

    def test_operation_value(self):
        self.assertEqual(encode(flags=[])["operation"], "segment encode")

    def test_flag_bits_wire_layout(self):
        for name, bit in FLAG_MASK.items():
            seg = bytes.fromhex(encode(flags=[name])["segment_hex"])
            self.assertEqual(seg[13], bit, name)

    def test_all_flags_combined(self):
        names = list(FLAG_MASK)
        seg = bytes.fromhex(encode(flags=names)["segment_hex"])
        self.assertEqual(seg[13], 0xFF)
        decoded = decode(encode(flags=names)["segment_hex"])
        self.assertEqual(decoded["flags"], names)  # 固定排列顺序

    def test_optionals_default_to_zero(self):
        result = encode()  # 无 ack/window/urgent/options/payload
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(struct.unpack("!I", seg[8:12])[0], 0)  # ack
        self.assertEqual(struct.unpack("!H", seg[14:16])[0], 0)  # window
        self.assertEqual(struct.unpack("!H", seg[18:20])[0], 0)  # urgent

    def test_hex_output_is_lowercase(self):
        result = encode(payload="deadbeefcafe", flags=["ACK"])
        self.assertEqual(result["segment_hex"],
                         result["segment_hex"].lower())
        self.assertIn("deadbeefcafe", result["segment_hex"])

    def test_odd_length_payload_checksum(self):
        result = encode(payload="010203", flags=["ACK"])
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(result["payload_length"], 3)
        pseudo = ref_pseudo("192.168.0.1", "10.0.0.1", len(seg))
        zeroed = bytearray(seg)
        struct.pack_into("!H", zeroed, 16, 0)
        self.assertEqual(
            struct.unpack("!H", seg[16:18])[0],
            ref_checksum(pseudo + bytes(zeroed)))


class OptionsEncodeTests(unittest.TestCase):
    def test_mss_encoding(self):
        result = encode(options=[{"type": 2, "mss": 1460}])
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(result["header_length"], 24)
        self.assertEqual(seg[20:24], bytes.fromhex("020405b4"))

    def test_mss_boundaries(self):
        for mss in (1, 65535):
            rc, _, err = run_cli(
                "encode", encode_obj(options=[{"type": 2, "mss": mss}]))
            self.assertEqual(rc, 0, err.decode())
        for mss in (0, 65536):
            rc, _, err = run_cli(
                "encode", encode_obj(options=[{"type": 2, "mss": mss}]))
            self.assertEqual(rc, 2)
            self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_mss_rejects_bool(self):
        rc, _, err = run_cli(
            "encode", encode_obj(options=[{"type": 2, "mss": True}]))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_nop_and_padding_to_four_bytes(self):
        # 4 字节 MSS + 1 个 NOP = 5，EOL/零填充补到 8。
        result = encode(options=[
            {"type": 2, "mss": 1000}, {"type": 1}])
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(result["header_length"], 28)
        self.assertEqual(seg[20:28],
                         bytes.fromhex("020403e801000000"))

    def test_options_fill_exactly_forty_bytes(self):
        # 40 个 NOP 恰好填满 40 字节选项区，无需零填充。
        result = encode(options=[{"type": 1}] * 40)
        self.assertEqual(result["header_length"], 60)
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(seg[20:60], b"\x01" * 40)

    def test_options_too_long(self):
        rc, _, err = run_cli(
            "encode", encode_obj(options=[{"type": 1}] * 41))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_eol_must_be_last(self):
        rc, _, err = run_cli("encode", encode_obj(options=[
            {"type": 0}, {"type": 1}]))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_unknown_option_preserved(self):
        result = encode(options=[
            {"type": 253, "length": 5, "data": "aabbcc"}])
        seg = bytes.fromhex(result["segment_hex"])
        # fd 05 aa bb cc + 3 字节零填充
        self.assertEqual(seg[20:28],
                         bytes.fromhex("fd05aabbcc000000"))

    def test_unknown_option_data_length_mismatch(self):
        rc, _, err = run_cli("encode", encode_obj(options=[
            {"type": 253, "length": 6, "data": "aabbcc"}]))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_unknown_option_length_bounds(self):
        for length in (0, 1, 256):
            rc, _, err = run_cli("encode", encode_obj(options=[
                {"type": 253, "length": length,
                 "data": "00" * max(0, length - 2)}]))
            self.assertEqual(rc, 2)


class DecodeTests(unittest.TestCase):
    def test_canonical_field_order(self):
        enc = encode(flags=["SYN", "ACK"], window=512,
                     options=[{"type": 2, "mss": 1460}],
                     payload="abcd")
        rc, out, err = run_cli("decode", decode_obj(enc["segment_hex"]))
        self.assertEqual(rc, 0, err.decode())
        keys = list(json.loads(out.decode()).keys())
        self.assertEqual(keys, [
            "source_ip", "destination_ip",
            "source_port", "destination_port",
            "sequence_number", "acknowledgment_number",
            "flags", "window", "urgent_pointer",
            "options", "payload",
            "segment_length", "header_length", "checksum"])

    def test_values_roundtrip_simple(self):
        enc = encode(
            source_port=80, destination_port=54321,
            sequence_number=0x12345678, acknowledgment_number=0x9abcdef0,
            flags=["FIN", "ACK"], window=1024, urgent_pointer=99,
            payload="feedface")
        dec = decode(enc["segment_hex"])
        self.assertEqual(dec["source_ip"], "192.168.0.1")
        self.assertEqual(dec["destination_ip"], "10.0.0.1")
        self.assertEqual(dec["source_port"], 80)
        self.assertEqual(dec["destination_port"], 54321)
        self.assertEqual(dec["sequence_number"], 0x12345678)
        self.assertEqual(dec["acknowledgment_number"], 0x9abcdef0)
        self.assertEqual(dec["flags"], ["FIN", "ACK"])
        self.assertEqual(dec["window"], 1024)
        self.assertEqual(dec["urgent_pointer"], 99)
        self.assertEqual(dec["payload"], "feedface")
        self.assertEqual(dec["segment_length"],
                         enc["header_length"] + enc["payload_length"])
        self.assertEqual(dec["header_length"], enc["header_length"])
        self.assertEqual(dec["checksum"], enc["checksum"])

    def test_structural_error_short_segment(self):
        rc, out, err = run_cli("decode", decode_obj("00" * 19))
        self.assertEqual(rc, 3)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_structural_error_data_offset_below_minimum(self):
        seg = bytearray.fromhex(encode()["segment_hex"])
        seg[12] = 0x40  # data offset = 4
        rc, out, err = run_cli("decode", decode_obj(bytes(seg).hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_structural_error_data_offset_past_end(self):
        seg = bytearray.fromhex(encode()["segment_hex"])
        seg[12] = 0xA0  # data offset = 10，但报文只有 20 字节
        rc, out, err = run_cli("decode", decode_obj(bytes(seg).hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_structural_error_reserved_bits(self):
        seg = bytearray.fromhex(encode()["segment_hex"])
        seg[12] = 0x51  # 低 4 位置位
        rc, _, err = run_cli("decode", decode_obj(bytes(seg).hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def _segment_with_options(self, option_bytes, data_offset):
        """构造一个带指定选项区的 20 字节头报文（不保证校验和正确）。"""
        header = bytearray(20)
        struct.pack_into(
            "!HHIIBBHHH", header, 0,
            1234, 4321, 0, 0, (data_offset << 4), 0, 0, 0, 0)
        return bytes(header) + option_bytes

    def test_bad_mss_length_rejected(self):
        opts = bytes.fromhex("020305b4") + b"\x00" * 4  # 长度 3 的 MSS
        seg = self._segment_with_options(opts, 6)
        rc, _, err = run_cli("decode", decode_obj(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_mss_zero_rejected(self):
        opts = bytes.fromhex("02040000") + b"\x00" * 4
        seg = self._segment_with_options(opts, 6)
        rc, _, err = run_cli("decode", decode_obj(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_option_length_below_two(self):
        opts = bytes.fromhex("0501") + b"\x00" * 6
        seg = self._segment_with_options(opts, 6)
        rc, _, err = run_cli("decode", decode_obj(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_option_extends_past_header(self):
        opts = bytes.fromhex("fd0a" + "00" * 6)  # 声称 10 字节
        seg = self._segment_with_options(opts, 6)
        rc, _, err = run_cli("decode", decode_obj(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_truncated_option_length_byte(self):
        seg = self._segment_with_options(bytes.fromhex("fd"), 6)
        rc, _, err = run_cli("decode", decode_obj(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_nonzero_padding_after_eol(self):
        opts = bytes.fromhex("0001") + b"\x00" * 6
        seg = self._segment_with_options(opts, 6)
        rc, _, err = run_cli("decode", decode_obj(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_checksum_mismatch(self):
        enc = encode(payload="abcd", flags=["ACK"])
        bad = bytearray.fromhex(enc["segment_hex"])
        bad[-1] ^= 0xFF  # 篡改负载
        rc, out, err = run_cli("decode", decode_obj(bytes(bad).hex()))
        self.assertEqual(rc, 4)
        self.assertEqual(out, b"")
        envelope = json.loads(err)
        self.assertEqual(envelope["error"], "ChecksumError")

    def test_checksum_uses_address_context(self):
        enc = encode(payload="abcd", flags=["ACK"])
        # 换一组地址上下文 -> 伪首部不同 -> 校验和不匹配
        rc, _, err = run_cli(
            "decode", decode_obj(enc["segment_hex"],
                                 src="192.168.0.2", dst="10.0.0.1"))
        self.assertEqual(rc, 4)
        self.assertEqual(json.loads(err)["error"], "ChecksumError")

    def test_unknown_option_decoded_raw(self):
        enc = encode(options=[
            {"type": 77, "length": 4, "data": "1122"}])
        dec = decode(enc["segment_hex"])
        self.assertEqual(dec["options"], [
            {"type": 77, "length": 4, "data": "1122"},
        ])

    def test_nop_and_eol_appear_in_output(self):
        enc = encode(options=[{"type": 2, "mss": 1460}, {"type": 1}])
        dec = decode(enc["segment_hex"])
        self.assertEqual(dec["options"], [
            {"type": 2, "mss": 1460},
            {"type": 1},
            {"type": 0},
        ])
        # 无选项时，20 字节头中也没有 EOL 项。
        self.assertEqual(decode(encode()["segment_hex"])["options"], [])


class RoundTripTests(unittest.TestCase):
    def _roundtrip(self, **enc_overrides):
        enc = encode(**enc_overrides)
        dec = decode(enc["segment_hex"])
        rebuilt_input = {
            "source_ip": dec["source_ip"],
            "destination_ip": dec["destination_ip"],
            "source_port": dec["source_port"],
            "destination_port": dec["destination_port"],
            "sequence_number": dec["sequence_number"],
            "acknowledgment_number": dec["acknowledgment_number"],
            "flags": dec["flags"],
            "window": dec["window"],
            "urgent_pointer": dec["urgent_pointer"],
            "options": dec["options"],
            "payload": dec["payload"],
        }
        rc, out, err = run_cli("encode", rebuilt_input)
        self.assertEqual(rc, 0, err.decode())
        self.assertEqual(
            json.loads(out)["segment_hex"], enc["segment_hex"])
        return enc, dec

    def test_matrix(self):
        flag_sets = [
            [], ["SYN"], ["FIN", "ACK"], list(FLAG_MASK),
            ["URG", "ECE", "CWR"],
        ]
        payloads = ["", "00", "010203", "ff" * 100, "abcdef"]
        option_sets = [
            [],
            [{"type": 1}],
            [{"type": 2, "mss": 1}, {"type": 2, "mss": 65535}],
            [{"type": 1}, {"type": 1}, {"type": 1}],
            [{"type": 253, "length": 2, "data": ""}],
            [{"type": 2, "mss": 1460}, {"type": 1},
             {"type": 5, "length": 8, "data": "010203040506"},
             {"type": 1}],
        ]
        for flags in flag_sets:
            for payload in payloads:
                for options in option_sets:
                    self._roundtrip(
                        flags=flags, payload=payload,
                        options=options, window=4000,
                        urgent_pointer=16)

    def test_eol_roundtrip(self):
        enc = encode(options=[{"type": 2, "mss": 1460},
                              {"type": 1}, {"type": 0}])
        dec = decode(enc["segment_hex"])
        rebuilt = {
            "source_ip": "192.168.0.1", "destination_ip": "10.0.0.1",
            "source_port": 1234, "destination_port": 4321,
            "sequence_number": 0, "flags": [],
            "options": dec["options"],
        }
        rc, out, err = run_cli("encode", rebuilt)
        self.assertEqual(rc, 0, err.decode())
        self.assertEqual(json.loads(out)["segment_hex"],
                         enc["segment_hex"])

    def test_wire_nop_padding_roundtrip(self):
        # 线上常见：用 NOP（而非 EOL+零）补齐选项区，同样必须逐字节往返。
        enc = encode(options=[
            {"type": 2, "mss": 1460},
            {"type": 253, "length": 5, "data": "aabbcc"}])
        seg = bytearray.fromhex(enc["segment_hex"])
        hlen = enc["header_length"]
        # 选项 9 字节 -> 末 3 字节是零填充，替换为 NOP。
        self.assertEqual(seg[hlen - 3:hlen], b"\x00\x00\x00")
        seg[hlen - 3:hlen] = b"\x01\x01\x01"
        struct.pack_into("!H", seg, 16, 0)
        pseudo = ref_pseudo("192.168.0.1", "10.0.0.1", len(seg))
        struct.pack_into("!H", seg, 16,
                         ref_checksum(pseudo + bytes(seg)))

        dec = decode(bytes(seg).hex())
        self.assertEqual(dec["options"][-3:],
                         [{"type": 1}, {"type": 1}, {"type": 1}])
        rebuilt = {
            "source_ip": dec["source_ip"],
            "destination_ip": dec["destination_ip"],
            "source_port": dec["source_port"],
            "destination_port": dec["destination_port"],
            "sequence_number": dec["sequence_number"],
            "acknowledgment_number": dec["acknowledgment_number"],
            "flags": dec["flags"],
            "window": dec["window"],
            "urgent_pointer": dec["urgent_pointer"],
            "options": dec["options"],
            "payload": dec["payload"],
        }
        rc, out, err = run_cli("encode", rebuilt)
        self.assertEqual(rc, 0, err.decode())
        self.assertEqual(json.loads(out)["segment_hex"], bytes(seg).hex())


class PayloadLimitTests(unittest.TestCase):
    def test_default_limit_boundary(self):
        rc1, _, _ = run_cli(
            "encode", encode_obj(payload="00" * 1460))
        self.assertEqual(rc1, 0)
        rc2, out, err = run_cli(
            "encode", encode_obj(payload="00" * 1461))
        self.assertEqual(rc2, 5)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "SegmentSizeError")

    def test_custom_limit_zero(self):
        rc, _, _ = run_cli("encode", encode_obj(
            payload="", maximum_payload_length=0))
        self.assertEqual(rc, 0)
        rc2, out, err = run_cli("encode", encode_obj(
            payload="00", maximum_payload_length=0))
        self.assertEqual(rc2, 5)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "SegmentSizeError")

    def test_no_truncation(self):
        # 超限时绝不能返回截断后的报文：直接失败，stdout 为空。
        rc, out, err = run_cli("encode", encode_obj(
            payload="00" * 2000, maximum_payload_length=10))
        self.assertEqual(rc, 5)
        self.assertEqual(out, b"")


class ParameterValidationTests(unittest.TestCase):
    def _expect_parameter_error(self, obj, *, raw=None):
        rc, out, err = run_cli("encode", obj, raw=raw)
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        envelope = json.loads(err)
        self.assertEqual(envelope["error"], "ParameterError")
        # 固定键序 error, message
        self.assertEqual(list(envelope.keys()), ["error", "message"])
        return envelope["message"]

    def test_invalid_json(self):
        rc, out, err = run_cli("encode", raw=b"{not json")
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_non_utf8_input(self):
        rc, out, err = run_cli("encode", raw=b"\xff\xfe")
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_top_level_not_object(self):
        for raw in (b"[1,2]", b"5", b'"x"', b"null"):
            rc, out, err = run_cli("encode", raw=raw)
            self.assertEqual(rc, 2, raw)
            self.assertEqual(out, b"")
            self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_missing_required_keys(self):
        base = encode_obj()
        for key in ("source_ip", "destination_ip", "source_port",
                    "destination_port", "sequence_number", "flags"):
            obj = dict(base)
            del obj[key]
            self._expect_parameter_error(obj)

    def test_bool_rejected_for_every_integer(self):
        base = encode_obj()
        for key in ("source_port", "destination_port",
                    "sequence_number", "acknowledgment_number",
                    "window", "urgent_pointer",
                    "maximum_payload_length"):
            self._expect_parameter_error(dict(base, **{key: True}))
            self._expect_parameter_error(dict(base, **{key: False}))

    def test_integer_ranges(self):
        cases = {
            "source_port": (-1, 65536),
            "destination_port": (-1, 65536),
            "sequence_number": (-1, 2 ** 32),
            "acknowledgment_number": (-1, 2 ** 32),
            "window": (-1, 65536),
            "urgent_pointer": (-1, 65536),
        }
        for key, values in cases.items():
            for value in values:
                self._expect_parameter_error(
                    dict(encode_obj(), **{key: value}))

    def test_wrong_types(self):
        base = encode_obj()
        self._expect_parameter_error(dict(base, source_port="80"))
        self._expect_parameter_error(dict(base, source_port=1.5))
        self._expect_parameter_error(dict(base, flags="SYN"))
        self._expect_parameter_error(dict(base, flags=[1]))
        self._expect_parameter_error(dict(base, payload=123))
        self._expect_parameter_error(dict(base, options={}))

    def test_odd_hex_rejected(self):
        self._expect_parameter_error(dict(encode_obj(), payload="abc"))

    def test_invalid_hex_rejected(self):
        self._expect_parameter_error(dict(encode_obj(), payload="zz"))

    def test_decode_odd_hex_rejected(self):
        rc, out, err = run_cli("decode", decode_obj("abc"))
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_decode_empty_segment_rejected(self):
        rc, _, err = run_cli(
            "decode", {"addresses": {
                "source_ip": "1.2.3.4",
                "destination_ip": "5.6.7.8"}, "segment": ""})
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_ipv4_canonical_only(self):
        for bad in ("1.2.3", "1.2.3.4.5", "256.0.0.1", "1.2.3.-1",
                    "01.2.3.4", "1.02.3.4", " 1.2.3.4", "1.2.3.4 ",
                    "1.2.3.a", "0x1.2.3.4", "0.0.0.0 ", "1…2.3.4",
                    "999.999.999.999"):
            self._expect_parameter_error(
                dict(encode_obj(), source_ip=bad))

    def test_ipv4_accepted(self):
        for good in ("0.0.0.0", "255.255.255.255", "10.0.0.1"):
            rc, _, err = run_cli(
                "encode", dict(encode_obj(), source_ip=good))
            self.assertEqual(rc, 0, err.decode())

    def test_duplicate_and_unknown_flags(self):
        self._expect_parameter_error(
            dict(encode_obj(), flags=["SYN", "SYN"]))
        self._expect_parameter_error(
            dict(encode_obj(), flags=["ACK", "ack"]))
        self._expect_parameter_error(
            dict(encode_obj(), flags=["NS"]))

    def test_decode_missing_address_context(self):
        rc, _, err = run_cli(
            "decode", {"segment": "00" * 20})
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_bad_usage(self):
        proc = subprocess.run(
            [PYTHON, "tcp.py", "bogus"], capture_output=True)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            json.loads(proc.stderr)["error"], "ParameterError")


class DeterminismTests(unittest.TestCase):
    def test_byte_identical_repeated_output(self):
        obj = encode_obj(
            flags=["SYN", "ACK"], window=1024,
            options=[{"type": 2, "mss": 1460}, {"type": 1}],
            payload="deadbeef")
        rc1, out1, _ = run_cli("encode", obj)
        rc2, out2, _ = run_cli("encode", obj)
        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(out1, out2)

    def test_no_insignificant_whitespace(self):
        rc, out, _ = run_cli("encode", encode_obj(flags=[]))
        self.assertEqual(rc, 0)
        # 紧凑 JSON 分隔符（operation 的值 "segment encode" 内含一个空格）。
        self.assertNotIn(b": ", out)
        self.assertNotIn(b", ", out)
        self.assertTrue(out.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
