"""Bounded Lua 5.2 float32 chunk inspection, never executes game scripts.

Structure follows supplied TFTB headers. Opcode mapping must be independently
verified against TFTB luaV_execute before using listings as patch evidence.
"""
import json
import struct

OPS = "MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG".split()


class Chunk:
    def __init__(self, data):
        self.data, self.pos = data, 0
        header = self.take(18)
        if header != bytes.fromhex("1b4c7561520001040404040019930d0a1a0a"):
            raise ValueError(f"Unsupported Lua52 header {header.hex()}")
        self.root = self.proto()
        if self.pos != len(data):
            raise ValueError(f"Unparsed bytes: {len(data) - self.pos}")

    def take(self, size):
        if size < 0 or self.pos + size > len(self.data):
            raise ValueError("Lua read outside input")
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def count(self, minimum=1):
        count = self.u32()
        if count > (len(self.data) - self.pos) // minimum:
            raise ValueError("Lua count outside input")
        return count

    def string(self):
        size = self.u32()
        if not size:
            return None
        value = self.take(size)
        if value[-1] != 0:
            raise ValueError("Lua string lacks terminator")
        return value[:-1].decode("utf-8", errors="replace")

    def constant(self):
        kind = self.take(1)[0]
        if kind == 0:
            return None
        if kind == 1:
            return bool(self.take(1)[0])
        if kind == 3:
            return struct.unpack("<f", self.take(4))[0]
        if kind == 4:
            return self.string()
        raise ValueError(f"Unknown constant type {kind}")

    def proto(self):
        first, last = self.u32(), self.u32()
        params, vararg, stack = self.take(3)
        code_offset = self.pos + 4
        code = [self.u32() for _ in range(self.count(4))]
        constants = [self.constant() for _ in range(self.count())]
        children = [self.proto() for _ in range(self.count(11))]
        upvalue_binding = [tuple(self.take(2)) for _ in range(self.count(2))]
        source = self.string()
        lines = [self.u32() for _ in range(self.count(4))]
        locals_ = [{"name": self.string(), "start": self.u32(), "end": self.u32()} for _ in range(self.count(12))]
        upvalues = [self.string() for _ in range(self.count(4))]
        if len(lines) not in (0, len(code)) or len(upvalues) not in (0, len(upvalue_binding)):
            raise ValueError("Lua debug counts mismatch")
        return dict(source=source, first=first, last=last, params=params, vararg=vararg,
                    stack=stack, code_offset=code_offset, code=code, constants=constants,
                    children=children, upvalue_binding=upvalue_binding, lines=lines,
                    locals=locals_, upvalues=upvalues)


def walk(proto, name="root"):
    yield name, proto
    for index, child in enumerate(proto["children"]):
        yield from walk(child, f"{name}/{index}")


def listing(proto):
    out = []
    for name, node in walk(proto):
        out.append(f"FUNCTION {name} lines={node['first']}..{node['last']} params={node['params']} stack={node['stack']} upvalues={node['upvalues']}")
        out.append("constants=" + json.dumps(node["constants"], ensure_ascii=False))
        for pc, word in enumerate(node["code"]):
            op, a, b, c = word & 63, (word >> 6) & 255, (word >> 23) & 511, (word >> 14) & 511
            bx, sbx = word >> 14, (word >> 14) - 131071
            opcode = OPS[op] if op < len(OPS) else "EXTRA"
            rk = lambda register: repr(node["constants"][register - 256]) if register >= 256 and register - 256 < len(node["constants"]) else f"R{register}"
            detail = f"R{a} B={b} C={c}"
            if opcode in ("LOADK",):
                detail = f"R{a} K{bx}={node['constants'][bx]!r}" if bx < len(node["constants"]) else f"INVALID K{bx}"
            elif opcode in ("GETTABLE", "SETTABLE", "SELF", "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "EQ", "LT", "LE"):
                detail = f"R{a} {rk(b)} {rk(c)}"
            elif opcode == "GETTABUP":
                detail = f"R{a} UP{b}[{rk(c)}]"
            elif opcode == "SETTABUP":
                detail = f"UP{a}[{rk(b)}] := {rk(c)}"
            elif opcode in ("JMP", "FORLOOP", "FORPREP", "TFORLOOP"):
                detail = f"R{a} ->PC{pc + 1 + sbx} delta={sbx}"
            elif opcode == "CLOSURE":
                detail = f"R{a} child{bx}"
            line = node["lines"][pc] if node["lines"] else 0
            out.append(f"{pc:04} L{line:04} @{node['code_offset'] + pc * 4:08x} {opcode:10} {detail} [{word:08x}]")
    return out


def self_check():
    header = bytes.fromhex("1b4c7561520001040404040019930d0a1a0a")
    fixture = header + bytes(8) + bytes((0, 1, 2)) + bytes(32)
    chunk = Chunk(fixture)
    assert chunk.pos == len(fixture) and chunk.root["stack"] == 2
    try:
        Chunk(fixture[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("Truncated Lua accepted")
    print("Lua52 structural self-check OK")


if __name__ == "__main__":
    self_check()
