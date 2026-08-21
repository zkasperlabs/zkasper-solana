#!/usr/bin/env python3
"""A `cargo-zisk wrap --plonk` output -> the four hex fields zkasper-solana reads.

`proofBytes` is the Vec<u8> the ProofBody::Plonk tag opens with. The three key
fields sit at the end: [publics_full(68)][rootc(4)][program_vk(4)][hash_mode].
Both keys are four u64s rendered big-endian, as the fixture writes them, and
`publicValues` is the 64-word window rendered little-endian.
"""
import json, sys

WORD = 9  # bincode varint for a value over 2^32: 0xfd + eight bytes


def rd_varint(b, i):
    t = b[i]
    if t < 251:
        return t, i + 1
    w = {251: 2, 252: 4, 253: 8, 254: 16}[t]
    return int.from_bytes(b[i + 1:i + 1 + w], 'little'), i + 1 + w


def rd_vec_u64(b, i, expect=None):
    n, i = rd_varint(b, i)
    if expect is not None and n != expect:
        raise ValueError(f'expected {expect} words at {i}, found {n}')
    out = []
    for _ in range(n):
        v, i = rd_varint(b, i)
        out.append(v)
    return out, i


def parse(path):
    b = open(path, 'rb').read()
    if b[0] != 1:
        raise ValueError('not a ProofBody::Plonk')
    n, i = rd_varint(b, 1)
    if n != 768:
        raise ValueError(f'proof is {n} bytes, not 768')
    proof_bytes = b[i:i + n]

    tail = len(b) - 1 - 2 * (1 + 4 * WORD)          # both keys are full-width words
    rootc, j = rd_vec_u64(b, tail, expect=4)
    program_vk, j = rd_vec_u64(b, j, expect=4)
    if j + 1 != len(b):
        raise ValueError('trailing bytes after program_vk')

    # publics_full ends where rootc begins; its 64 window words are narrower than
    # its 4 key words, so find the length byte that decodes to exactly that span.
    for p in range(tail - 1, tail - 800, -1):
        if b[p] != 68:
            continue
        try:
            publics_full, end = rd_vec_u64(b, p, expect=68)
        except (ValueError, KeyError, IndexError):
            continue
        if end == tail and publics_full[:4] == program_vk:
            break
    else:
        raise ValueError('no 68-word publics_full ending at rootc')

    return {
        'programVK': '0x' + b''.join(w.to_bytes(8, 'big') for w in program_vk).hex(),
        'rootCVadcopFinal': '0x' + b''.join(w.to_bytes(8, 'big') for w in rootc).hex(),
        'publicValues': '0x' + b''.join(w.to_bytes(8, 'little') for w in publics_full[4:]).hex(),
        'proofBytes': '0x' + proof_bytes.hex(),
    }


if __name__ == '__main__':
    out = parse(sys.argv[1])
    text = '{\n' + ',\n'.join(f'  "{k}": "{v}"' for k, v in out.items()) + '\n}\n'
    if len(sys.argv) > 2:
        open(sys.argv[2], 'w').write(text)
    else:
        sys.stdout.write(text)
