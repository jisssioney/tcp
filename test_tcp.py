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

SRC = "192.168.0.1"
DST = "10.0.0.1"


# ---------------------------------------------------------------------------
# 独立参考校验和，用于交叉验证 tcp.internet_checksum
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


FLAG_BIT = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
    "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}


# ---------------------------------------------------------------------------
# CLI 辅助
# ---------------------------------------------------------------------------

def run_cli(subcommand, payload_obj=None, *, raw=None):
    if raw is None:
        raw = json.dumps(payload_obj).encode("utf-8")
    proc = subprocess.run(
        [PYTHON, "tcp.py", "segment", subcommand],
        input=raw, capture_output=True)
    return proc.returncode, proc.stdout, proc.stderr


def encode_input(**overrides):
    obj = {
        "source_ip": SRC,
        "destination_ip": DST,
        "source_port": 1234,
        "destination_port": 4321,
        "sequence_number": 0,
        "flags": [],
    }
    obj.update(overrides)
    return obj


def encode(**overrides):
    rc, out, err = run_cli("encode", encode_input(**overrides))
    assert rc == 0, err.decode()
    return json.loads(out)


def decode_input(segment_hex, src=SRC, dst=DST):
    return {
        "addresses": {"source_ip": src, "destination_ip": dst},
        "segment": segment_hex,
    }


def decode(segment_hex, src=SRC, dst=DST):
    rc, out, err = run_cli("decode", decode_input(segment_hex, src, dst))
    assert rc == 0, err.decode()
    return json.loads(out)


# ---------------------------------------------------------------------------
# 校验和
# ---------------------------------------------------------------------------

class ChecksumTests(unittest.TestCase):
    def test_known_syn_vector(self):
        segment = bytes.fromhex(
            "04d210e100000000000000005002ffff00000000")
        pseudo = ref_pseudo(SRC, DST, len(segment))
        self.assertEqual(ref_checksum(pseudo + segment), 0xcf85)
        self.assertEqual(tcp.internet_checksum(pseudo + segment), 0xcf85)

    def test_odd_length_pads_zero_only_in_computation(self):
        for blob in (b"\x01", b"\x01\x00\x02", b"abcde"):
            self.assertEqual(
                tcp.internet_checksum(blob), ref_checksum(blob))

    def test_checksum_of_all_zeros_is_ffff(self):
        self.assertEqual(tcp.internet_checksum(b"\x00\x00"), 0xffff)


# ---------------------------------------------------------------------------
# encode
# ---------------------------------------------------------------------------

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
        rc, out, err = run_cli("encode", encode_input(flags=["FIN"]))
        self.assertEqual(rc, 0, err.decode())
        self.assertEqual(
            list(json.loads(out.decode()).keys()),
            ["operation", "segment_hex", "header_length",
             "payload_length", "checksum"])

    def test_operation_value(self):
        self.assertEqual(encode()["operation"], "segment encode")

    def test_flag_bits_on_wire(self):
        for name, bit in FLAG_BIT.items():
            seg = bytes.fromhex(encode(flags=[name])["segment_hex"])
            self.assertEqual(seg[13], bit, name)

    def test_all_flags_combined_and_ordered(self):
        names = list(FLAG_BIT)
        result = encode(flags=names)
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(seg[13], 0xFF)
        self.assertEqual(decode(result["segment_hex"])["flags"], names)

    def test_optional_fields_default_to_zero_or_empty(self):
        result = encode()
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(struct.unpack("!I", seg[8:12])[0], 0)  # ack
        self.assertEqual(struct.unpack("!H", seg[14:16])[0], 0)  # window
        self.assertEqual(struct.unpack("!H", seg[18:20])[0], 0)  # urgent
        self.assertEqual(result["header_length"], 20)
        self.assertEqual(decode(result["segment_hex"])["options"], [])

    def test_hex_is_lowercase(self):
        result = encode(payload="deadbeefcafe", flags=["ACK"])
        self.assertEqual(result["segment_hex"],
                         result["segment_hex"].lower())
        self.assertTrue(result["segment_hex"].endswith("deadbeefcafe"))

    def test_odd_length_payload_checksum(self):
        result = encode(payload="010203", flags=["ACK"])
        seg = bytes.fromhex(result["segment_hex"])
        zeroed = bytearray(seg)
        struct.pack_into("!H", zeroed, 16, 0)
        pseudo = ref_pseudo(SRC, DST, len(seg))
        self.assertEqual(
            struct.unpack("!H", seg[16:18])[0],
            ref_checksum(pseudo + bytes(zeroed)))


# ---------------------------------------------------------------------------
# 选项编码
# ---------------------------------------------------------------------------

class OptionsEncodeTests(unittest.TestCase):
    def test_mss_encoding(self):
        result = encode(options=[{"type": 2, "mss": 1460}])
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(result["header_length"], 24)
        self.assertEqual(seg[20:24], bytes.fromhex("020405b4"))

    def test_mss_boundaries(self):
        for mss, ok in ((1, True), (65535, True), (0, False), (65536, False)):
            rc, _, err = run_cli(
                "encode", encode_input(options=[{"type": 2, "mss": mss}]))
            self.assertEqual(rc, 0 if ok else 2, mss)
            if not ok:
                self.assertEqual(
                    json.loads(err)["error"], "ParameterError")

    def test_mss_rejects_bool(self):
        rc, _, err = run_cli(
            "encode", encode_input(options=[{"type": 2, "mss": True}]))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_nop_and_zero_padding(self):
        result = encode(options=[
            {"type": 2, "mss": 1000}, {"type": 1}])
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(result["header_length"], 28)
        self.assertEqual(seg[20:28], bytes.fromhex("020403e801000000"))

    def test_options_fill_exactly_forty_bytes(self):
        result = encode(options=[{"type": 1}] * 40)
        self.assertEqual(result["header_length"], 60)
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(seg[20:60], b"\x01" * 40)

    def test_options_too_long(self):
        rc, out, err = run_cli(
            "encode", encode_input(options=[{"type": 1}] * 41))
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_eol_must_be_last(self):
        rc, _, err = run_cli("encode", encode_input(
            options=[{"type": 0}, {"type": 1}]))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_unknown_option_preserved_verbatim(self):
        result = encode(options=[
            {"type": 253, "length": 5, "data": "aabbcc"}])
        seg = bytes.fromhex(result["segment_hex"])
        self.assertEqual(
            seg[20:28], bytes.fromhex("fd05aabbcc000000"))

    def test_unknown_option_data_length_mismatch(self):
        rc, _, err = run_cli("encode", encode_input(options=[
            {"type": 253, "length": 6, "data": "aabbcc"}]))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_unknown_option_length_bounds(self):
        for length in (0, 1, 256):
            data = "00" * max(0, length - 2)
            rc, _, err = run_cli("encode", encode_input(options=[
                {"type": 253, "length": length, "data": data}]))
            self.assertEqual(rc, 2, length)


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------

class DecodeTests(unittest.TestCase):
    def test_canonical_field_order(self):
        enc = encode(flags=["SYN", "ACK"], window=512,
                     options=[{"type": 2, "mss": 1460}],
                     payload="abcd")
        rc, out, err = run_cli("decode", decode_input(enc["segment_hex"]))
        self.assertEqual(rc, 0, err.decode())
        self.assertEqual(list(json.loads(out.decode()).keys()), [
            "source_ip", "destination_ip",
            "source_port", "destination_port",
            "sequence_number", "acknowledgment_number",
            "flags", "window", "urgent_pointer",
            "options", "payload",
            "segment_length", "header_length", "checksum"])

    def test_values_roundtrip(self):
        enc = encode(
            source_port=80, destination_port=54321,
            sequence_number=0x12345678,
            acknowledgment_number=0x9abcdef0,
            flags=["FIN", "ACK"], window=1024, urgent_pointer=99,
            payload="feedface")
        dec = decode(enc["segment_hex"])
        self.assertEqual(dec["source_ip"], SRC)
        self.assertEqual(dec["destination_ip"], DST)
        self.assertEqual(dec["source_port"], 80)
        self.assertEqual(dec["destination_port"], 54321)
        self.assertEqual(dec["sequence_number"], 0x12345678)
        self.assertEqual(dec["acknowledgment_number"], 0x9abcdef0)
        self.assertEqual(dec["flags"], ["FIN", "ACK"])
        self.assertEqual(dec["window"], 1024)
        self.assertEqual(dec["urgent_pointer"], 99)
        self.assertEqual(dec["payload"], "feedface")
        self.assertEqual(
            dec["segment_length"],
            enc["header_length"] + enc["payload_length"])
        self.assertEqual(dec["header_length"], enc["header_length"])
        self.assertEqual(dec["checksum"], enc["checksum"])

    def test_short_segment_is_format_error(self):
        rc, out, err = run_cli("decode", decode_input("00" * 19))
        self.assertEqual(rc, 3)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_data_offset_below_minimum(self):
        seg = bytearray.fromhex(encode()["segment_hex"])
        seg[12] = 0x40
        rc, _, err = run_cli("decode", decode_input(bytes(seg).hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_data_offset_past_end(self):
        seg = bytearray.fromhex(encode()["segment_hex"])
        seg[12] = 0xA0
        rc, _, err = run_cli("decode", decode_input(bytes(seg).hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_reserved_bits_must_be_zero(self):
        seg = bytearray.fromhex(encode()["segment_hex"])
        seg[12] = 0x51
        rc, _, err = run_cli("decode", decode_input(bytes(seg).hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def _segment_with_options(self, option_bytes, data_offset):
        header = bytearray(20)
        struct.pack_into(
            "!HHIIBBHHH", header, 0,
            1234, 4321, 0, 0, data_offset << 4, 0, 0, 0, 0)
        return bytes(header) + option_bytes

    def test_bad_mss_length_rejected(self):
        seg = self._segment_with_options(
            bytes.fromhex("020305b4") + b"\x00" * 4, 6)
        rc, _, err = run_cli("decode", decode_input(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_mss_zero_rejected(self):
        seg = self._segment_with_options(
            bytes.fromhex("02040000") + b"\x00" * 4, 6)
        rc, _, err = run_cli("decode", decode_input(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_option_length_below_two(self):
        seg = self._segment_with_options(
            bytes.fromhex("0501") + b"\x00" * 6, 6)
        rc, _, err = run_cli("decode", decode_input(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_option_extends_past_header(self):
        seg = self._segment_with_options(
            bytes.fromhex("fd0a" + "00" * 6), 6)
        rc, _, err = run_cli("decode", decode_input(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_truncated_option_length_byte(self):
        seg = self._segment_with_options(bytes.fromhex("fd"), 6)
        rc, _, err = run_cli("decode", decode_input(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_nonzero_padding_after_eol(self):
        seg = self._segment_with_options(
            bytes.fromhex("0001") + b"\x00" * 6, 6)
        rc, _, err = run_cli("decode", decode_input(seg.hex()))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(err)["error"], "SegmentFormatError")

    def test_checksum_mismatch(self):
        enc = encode(payload="abcd", flags=["ACK"])
        bad = bytearray.fromhex(enc["segment_hex"])
        bad[-1] ^= 0xFF
        rc, out, err = run_cli("decode", decode_input(bytes(bad).hex()))
        self.assertEqual(rc, 4)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "ChecksumError")

    def test_checksum_depends_on_address_context(self):
        enc = encode(payload="abcd", flags=["ACK"])
        rc, _, err = run_cli("decode", decode_input(
            enc["segment_hex"], src="192.168.0.2"))
        self.assertEqual(rc, 4)
        self.assertEqual(json.loads(err)["error"], "ChecksumError")

    def test_unknown_option_decoded_raw(self):
        enc = encode(options=[
            {"type": 77, "length": 4, "data": "1122"}])
        self.assertEqual(decode(enc["segment_hex"])["options"], [
            {"type": 77, "length": 4, "data": "1122"}])

    def test_nop_and_eol_appear_in_output(self):
        enc = encode(options=[
            {"type": 2, "mss": 1460}, {"type": 1}])
        self.assertEqual(decode(enc["segment_hex"])["options"], [
            {"type": 2, "mss": 1460},
            {"type": 1},
            {"type": 0},
        ])

    def test_empty_options_area(self):
        enc = encode()
        self.assertEqual(decode(enc["segment_hex"])["options"], [])


# ---------------------------------------------------------------------------
# decode -> encode 逐字节一致
# ---------------------------------------------------------------------------

class RoundTripTests(unittest.TestCase):
    def _roundtrip(self, **overrides):
        enc = encode(**overrides)
        dec = decode(enc["segment_hex"])
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
        self.assertEqual(
            json.loads(out)["segment_hex"], enc["segment_hex"])

    def test_matrix(self):
        flag_sets = [
            [], ["SYN"], ["FIN", "ACK"], list(FLAG_BIT),
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
                        flags=flags, payload=payload, options=options,
                        window=4000, urgent_pointer=16)

    def test_explicit_eol_roundtrip(self):
        enc = encode(options=[
            {"type": 2, "mss": 1460}, {"type": 1}, {"type": 0}])
        dec = decode(enc["segment_hex"])
        rebuilt = dict(encode_input(), options=dec["options"])
        rc, out, err = run_cli("encode", rebuilt)
        self.assertEqual(rc, 0, err.decode())
        self.assertEqual(
            json.loads(out)["segment_hex"], enc["segment_hex"])

    def test_wire_nop_padding_roundtrip(self):
        # 线上以 NOP（而非 EOL+零）补齐选项区，也必须逐字节往返。
        enc = encode(options=[
            {"type": 2, "mss": 1460},
            {"type": 253, "length": 5, "data": "aabbcc"}])
        seg = bytearray.fromhex(enc["segment_hex"])
        hlen = enc["header_length"]
        self.assertEqual(seg[hlen - 3:hlen], b"\x00\x00\x00")
        seg[hlen - 3:hlen] = b"\x01\x01\x01"
        struct.pack_into("!H", seg, 16, 0)
        pseudo = ref_pseudo(SRC, DST, len(seg))
        struct.pack_into(
            "!H", seg, 16, ref_checksum(pseudo + bytes(seg)))

        dec = decode(bytes(seg).hex())
        self.assertEqual(
            dec["options"][-3:],
            [{"type": 1}, {"type": 1}, {"type": 1}])
        rebuilt = dict(encode_input(), **{
            "acknowledgment_number": dec["acknowledgment_number"],
            "flags": dec["flags"],
            "window": dec["window"],
            "urgent_pointer": dec["urgent_pointer"],
            "options": dec["options"],
            "payload": dec["payload"],
        })
        rc, out, err = run_cli("encode", rebuilt)
        self.assertEqual(rc, 0, err.decode())
        self.assertEqual(
            json.loads(out)["segment_hex"], bytes(seg).hex())


# ---------------------------------------------------------------------------
# 负载长度限制
# ---------------------------------------------------------------------------

class PayloadLimitTests(unittest.TestCase):
    def test_default_limit_boundary(self):
        rc, _, _ = run_cli("encode", encode_input(payload="00" * 1460))
        self.assertEqual(rc, 0)
        rc, out, err = run_cli(
            "encode", encode_input(payload="00" * 1461))
        self.assertEqual(rc, 5)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "SegmentSizeError")

    def test_custom_limit_zero(self):
        rc, _, _ = run_cli("encode", encode_input(
            payload="", maximum_payload_length=0))
        self.assertEqual(rc, 0)
        rc, out, err = run_cli("encode", encode_input(
            payload="00", maximum_payload_length=0))
        self.assertEqual(rc, 5)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "SegmentSizeError")

    def test_no_truncation_on_overflow(self):
        rc, out, err = run_cli("encode", encode_input(
            payload="00" * 2000, maximum_payload_length=10))
        self.assertEqual(rc, 5)
        self.assertEqual(out, b"")


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------

class ParameterValidationTests(unittest.TestCase):
    def expect_parameter_error(self, obj=None, *, raw=None):
        rc, out, err = run_cli("encode", obj, raw=raw)
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        envelope = json.loads(err)
        self.assertEqual(envelope["error"], "ParameterError")
        self.assertEqual(list(envelope.keys()), ["error", "message"])

    def test_invalid_json(self):
        rc, out, err = run_cli("encode", raw=b"{not json")
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_non_utf8_input(self):
        rc, out, _ = run_cli("encode", raw=b"\xff\xfe")
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")

    def test_top_level_not_object(self):
        for raw in (b"[1,2]", b"5", b'"x"', b"null"):
            rc, out, _ = run_cli("encode", raw=raw)
            self.assertEqual(rc, 2, raw)
            self.assertEqual(out, b"", raw)

    def test_missing_required_keys(self):
        for key in ("source_ip", "destination_ip", "source_port",
                    "destination_port", "sequence_number", "flags"):
            obj = encode_input()
            del obj[key]
            self.expect_parameter_error(obj)

    def test_bool_rejected_for_every_integer(self):
        for key in ("source_port", "destination_port",
                    "sequence_number", "acknowledgment_number",
                    "window", "urgent_pointer",
                    "maximum_payload_length"):
            self.expect_parameter_error(dict(encode_input(), **{key: True}))
            self.expect_parameter_error(dict(encode_input(), **{key: False}))

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
                self.expect_parameter_error(
                    dict(encode_input(), **{key: value}))

    def test_wrong_types(self):
        self.expect_parameter_error(
            dict(encode_input(), source_port="80"))
        self.expect_parameter_error(
            dict(encode_input(), source_port=1.5))
        self.expect_parameter_error(dict(encode_input(), flags="SYN"))
        self.expect_parameter_error(dict(encode_input(), flags=[1]))
        self.expect_parameter_error(dict(encode_input(), payload=123))
        self.expect_parameter_error(dict(encode_input(), options={}))

    def test_odd_hex_rejected(self):
        self.expect_parameter_error(dict(encode_input(), payload="abc"))

    def test_invalid_hex_rejected(self):
        self.expect_parameter_error(dict(encode_input(), payload="zz"))

    def test_decode_odd_hex_rejected(self):
        rc, out, _ = run_cli("decode", decode_input("abc"))
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"")

    def test_decode_empty_segment_rejected(self):
        rc, _, err = run_cli("decode", {
            "addresses": {"source_ip": "1.2.3.4",
                          "destination_ip": "5.6.7.8"},
            "segment": ""})
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_ipv4_canonical_only(self):
        bad_values = (
            "1.2.3", "1.2.3.4.5", "256.0.0.1", "1.2.3.-1",
            "01.2.3.4", "1.02.3.4", " 1.2.3.4", "1.2.3.4 ",
            "1.2.3.a", "0x1.2.3.4", "1…2.3.4", "999.999.999.999",
        )
        for bad in bad_values:
            self.expect_parameter_error(
                dict(encode_input(), source_ip=bad))

    def test_ipv4_accepted(self):
        for good in ("0.0.0.0", "255.255.255.255", "10.0.0.1"):
            rc, _, err = run_cli(
                "encode", dict(encode_input(), source_ip=good))
            self.assertEqual(rc, 0, err.decode())

    def test_duplicate_and_unknown_flags(self):
        self.expect_parameter_error(
            dict(encode_input(), flags=["SYN", "SYN"]))
        self.expect_parameter_error(
            dict(encode_input(), flags=["ACK", "ack"]))
        self.expect_parameter_error(
            dict(encode_input(), flags=["NS"]))

    def test_decode_missing_address_context(self):
        rc, _, err = run_cli(
            "decode", {"segment": "00" * 20})
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(err)["error"], "ParameterError")

    def test_bad_usage(self):
        for argv in (["bogus"], ["segment"], ["segment", "bogus"],
                     ["packet", "encode"], ["segment", "encode", "x"]):
            proc = subprocess.run(
                [PYTHON, "tcp.py", *argv], capture_output=True)
            self.assertEqual(proc.returncode, 2, argv)
            self.assertEqual(proc.stdout, b"", argv)
            self.assertEqual(
                json.loads(proc.stderr)["error"], "ParameterError", argv)


# ---------------------------------------------------------------------------
# 确定性
# ---------------------------------------------------------------------------

class DeterminismTests(unittest.TestCase):
    def test_byte_identical_repeated_output(self):
        obj = encode_input(
            flags=["SYN", "ACK"], window=1024,
            options=[{"type": 2, "mss": 1460}, {"type": 1}],
            payload="deadbeef")
        rc1, out1, _ = run_cli("encode", obj)
        rc2, out2, _ = run_cli("encode", obj)
        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(out1, out2)

    def test_compact_json_single_line(self):
        rc, out, _ = run_cli("encode", encode_input())
        self.assertEqual(rc, 0)
        self.assertNotIn(b": ", out)
        self.assertNotIn(b", ", out)
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(out.count(b"\n"), 1)


if __name__ == "__main__":
    unittest.main()
