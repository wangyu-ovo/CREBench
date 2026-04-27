from __future__ import annotations


BLOCK_SIZE = 16
MIN_KEY_SIZE = 16
MAX_KEY_SIZE = 56

SBOX = [
    0x09D0C479, 0x28C8FFE0, 0x84AA6C39, 0x9DAD7287, 0x7DFF9BE3, 0xD4268361, 0xC96DA1D4, 0x7974CC93,
    0x85D0582E, 0x2A4B5705, 0x1CA16A62, 0xC3BD279D, 0x0F1F25E5, 0x5160372F, 0xC695C1FB, 0x4D7FF1E4,
    0xAE5F6BF4, 0x0D72EE46, 0xFF23DE8A, 0xB1CF8E83, 0xF14902E2, 0x3E981E42, 0x8BF53EB6, 0x7F4BF8AC,
    0x83631F83, 0x25970205, 0x76AFE784, 0x3A7931D4, 0x4F846450, 0x5C64C3F6, 0x210A5F18, 0xC6986A26,
    0x28F4E826, 0x3A60A81C, 0xD340A664, 0x7EA820C4, 0x526687C5, 0x7EDDD12B, 0x32A11D1D, 0x9C9EF086,
    0x80F6E831, 0xAB6F04AD, 0x56FB9B53, 0x8B2E095C, 0xB68556AE, 0xD2250B0D, 0x294A7721, 0xE21FB253,
    0xAE136749, 0xE82AAE86, 0x93365104, 0x99404A66, 0x78A784DC, 0xB69BA84B, 0x04046793, 0x23DB5C1E,
    0x46CAE1D6, 0x2FE28134, 0x5A223942, 0x1863CD5B, 0xC190C6E3, 0x07DFB846, 0x6EB88816, 0x2D0DCC4A,
    0xA4CCAE59, 0x3798670D, 0xCBFA9493, 0x4F481D45, 0xEAFC8CA8, 0xDB1129D6, 0xB0449E20, 0x0F5407FB,
    0x6167D9A8, 0xD1F45763, 0x4DAA96C3, 0x3BEC5958, 0xABABA014, 0xB6CCD201, 0x38D6279F, 0x02682215,
    0x8F376CD5, 0x092C237E, 0xBFC56593, 0x32889D2C, 0x854B3E95, 0x05BB9B43, 0x7DCD5DCD, 0xA02E926C,
    0xFAE527E5, 0x36A1C330, 0x3412E1AE, 0xF257F462, 0x3C4F1D71, 0x30A2E809, 0x68E5F551, 0x9C61BA44,
    0x5DED0AB8, 0x75CE09C8, 0x9654F93E, 0x698C0CCA, 0x243CB3E4, 0x2B062B97, 0x0F3B8D9E, 0x00E050DF,
    0xFC5D6166, 0xE35F9288, 0xC079550D, 0x0591AEE8, 0x8E531E74, 0x75FE3578, 0x2F6D829A, 0xF60B21AE,
    0x95E8EB8D, 0x6699486B, 0x901D7D9B, 0xFD6D6E31, 0x1090ACEF, 0xE0670DD8, 0xDAB2E692, 0xCD6D4365,
    0xE5393514, 0x3AF345F0, 0x6241FC4D, 0x460DA3A3, 0x7BCF3729, 0x8BF1D1E0, 0x14AAC070, 0x1587ED55,
    0x3AFD7D3E, 0xD2F29E01, 0x29A9D1F6, 0xEFB10C53, 0xCF3B870F, 0xB414935C, 0x664465ED, 0x024ACAC7,
    0x59A744C1, 0x1D2936A7, 0xDC580AA6, 0xCF574CA8, 0x040A7A10, 0x6CD81807, 0x8A98BE4C, 0xACCEA063,
    0xC33E92B5, 0xD1E0E03D, 0xB322517E, 0x2092BD13, 0x386B2C4A, 0x52E8DD58, 0x58656DFB, 0x50820371,
    0x41811896, 0xE337EF7E, 0xD39FB119, 0xC97F0DF6, 0x68FEA01B, 0xA150A6E5, 0x55258962, 0xEB6FF41B,
    0xD7C9CD7A, 0xA619CD9E, 0xBCF09576, 0x2672C073, 0xF003FB3C, 0x4AB7A50B, 0x1484126A, 0x487BA9B1,
    0xA64FC9C6, 0xF6957D49, 0x38B06A75, 0xDD805FCD, 0x63D094CF, 0xF51C999E, 0x1AA4D343, 0xB8495294,
    0xCE9F8E99, 0xBFFCD770, 0xC7C275CC, 0x378453A7, 0x7B21BE33, 0x397F41BD, 0x4E94D131, 0x92CC1F98,
    0x5915EA51, 0x99F861B7, 0xC9980A88, 0x1D74FD5F, 0xB0A495F8, 0x614DEED0, 0xB5778EEA, 0x5941792D,
    0xFA90C1F8, 0x33F824B4, 0xC4965372, 0x3FF6D550, 0x4CA5FEC0, 0x8630E964, 0x5B3FBBD6, 0x7DA26A48,
    0xB203231A, 0x04297514, 0x2D639306, 0x2EB13149, 0x16A45272, 0x532459A0, 0x8E5F4872, 0xF966C7D9,
    0x07128DC0, 0x0D44DB62, 0xAFC8D52D, 0x06316131, 0xD838E7CE, 0x1BC41D00, 0x3A2E8C0F, 0xEA83837E,
    0xB984737D, 0x13BA4891, 0xC4F8B949, 0xA6D6ACB3, 0xA215CDCE, 0x8359838B, 0x6BD1AA31, 0xF579DD52,
    0x21B93F93, 0xF5176781, 0x187DFDDE, 0xE94AEB76, 0x2B38FD54, 0x431DE1DA, 0xAB394825, 0x9AD3048F,
    0xDFEA32AA, 0x659473E3, 0x623F7863, 0xF3346C59, 0xAB3AB685, 0x3346A90B, 0x6B56443E, 0xC6DE01F8,
    0x8D421FC0, 0x9B0ED10C, 0x88F1A1E9, 0x54C1F029, 0x7DEAD57B, 0x8D7BA426, 0x4CF5178A, 0x551A7CCA,
    0x1A9A5F08, 0xFCD651B9, 0x25605182, 0xE11FC6C3, 0xB6FD9676, 0x337B3027, 0xB7C8EB14, 0x9E5FD030,
    0x6B57E354, 0xAD913CF7, 0x7E16688D, 0x58872A69, 0x2C2FC7DF, 0xE389CCC6, 0x30738DF1, 0x0824A734,
    0xE1797A8B, 0xA4A8D57B, 0x5B5D193B, 0xC8A8309B, 0x73F9A978, 0x73398D32, 0x0F59573E, 0xE9DF2B03,
    0xE8A5B6C8, 0x848D0704, 0x98DF93C2, 0x720A1DC3, 0x684F259A, 0x943BA848, 0xA6370152, 0x863B5EA3,
    0xD17B978B, 0x6D9B58EF, 0x0A700DD4, 0xA73D36BF, 0x8E6A0829, 0x8695BC14, 0xE35B3447, 0x933AC568,
    0x8894B022, 0x2F511C27, 0xDDFBCC3C, 0x006662B6, 0x117C83FE, 0x4E12B414, 0xC2BCA766, 0x3A2FEC10,
    0xF4562420, 0x55792E2A, 0x46F5D857, 0xCEDA25CE, 0xC3601D3B, 0x6C00AB46, 0xEFAC9C28, 0xB3C35047,
    0x611DFEE3, 0x257C3207, 0xFDD58482, 0x3B14D84F, 0x23BECB64, 0xA075F3A3, 0x088F8EAD, 0x07ADF158,
    0x7796943C, 0xFACABF3D, 0xC09730CD, 0xF7679969, 0xDA44E9ED, 0x2C854C12, 0x35935FA3, 0x2F057D9F,
    0x690624F8, 0x1CB0BAFD, 0x7B0DBDC6, 0x810F23BB, 0xFA929A1A, 0x6D969A17, 0x6742979B, 0x74AC7D05,
    0x010E65C4, 0x86A3D963, 0xF907B5A0, 0xD0042BD3, 0x158D7D03, 0x287A8255, 0xBBA8366F, 0x096EDC33,
    0x21916A7B, 0x77B56B86, 0x951622F9, 0xA6C5E650, 0x8CEA17D1, 0xCD8C62BC, 0xA3D63433, 0x358A68FD,
    0x0F9B9D3C, 0xD6AA295B, 0xFE33384A, 0xC000738E, 0xCD67EB2F, 0xE2EB6DC2, 0x97338B02, 0x06C9F246,
    0x419CF1AD, 0x2B83C045, 0x3723F18A, 0xCB5B3089, 0x160BEAD7, 0x5D494656, 0x35F8A74B, 0x1E4E6C9E,
    0x000399BD, 0x67466880, 0xB4174831, 0xACF423B2, 0xCA815AB3, 0x5A6395E7, 0x302A67C5, 0x8BDB446B,
    0x108F8FA4, 0x10223EDA, 0x92B8B48B, 0x7F38D0EE, 0xAB2701D4, 0x0262D415, 0xAF224A30, 0xB3D88ABA,
    0xF8B2C3AF, 0xDAF7EF70, 0xCC97D3B7, 0xE9614B6C, 0x2BAEBFF4, 0x70F687CF, 0x386C9156, 0xCE092EE5,
    0x01E87DA6, 0x6CE91E6A, 0xBB7BCC84, 0xC7922C20, 0x9D3B71FD, 0x060E41C6, 0xD7590F15, 0x4E03BB47,
    0x183C198E, 0x63EEB240, 0x2DDBF49A, 0x6D5CBA54, 0x923750AF, 0xF9E14236, 0x7838162B, 0x59726C72,
    0x81B66760, 0xBB2926C1, 0x48A0CE0D, 0xA6C0496D, 0xAD43507B, 0x718D496A, 0x9DF057AF, 0x44B1BDE6,
    0x054356DC, 0xDE7CED35, 0xD51A138B, 0x62088CC9, 0x35830311, 0xC96EFCA2, 0x686F86EC, 0x8E77CB68,
    0x63E1D6B8, 0xC80F9778, 0x79C491FD, 0x1B4C67F2, 0x72698D7D, 0x5E368C31, 0xF7D95E2E, 0xA1D3493F,
    0xDCD9433E, 0x896F1552, 0x4BC4CA7A, 0xA6D1BAF4, 0xA5A96DCC, 0x0BEF8B46, 0xA169FDA7, 0x74DF40B7,
    0x4E208804, 0x9A756607, 0x038E87C8, 0x20211E44, 0x8B7AD4BF, 0xC6403F35, 0x1848E36D, 0x80BDB038,
    0x1E62891C, 0x643D2107, 0xBF04D6F8, 0x21092C8C, 0xF644F389, 0x0778404E, 0x7B78ADB8, 0xA2C52D53,
    0x42157ABE, 0xA2253E2E, 0x7BF3F4AE, 0x80F594F9, 0x953194E7, 0x77EB92ED, 0xB3816930, 0xDA8D9336,
    0xBF447469, 0xF26D9483, 0xEE6FAED5, 0x71371235, 0xDE425F73, 0xB4E59F43, 0x7DBE2D4E, 0x2D37B185,
    0x49DC9A63, 0x98C39D98, 0x1301C9A2, 0x389B1BBF, 0x0C18588D, 0xA421C1BA, 0x7AA3865C, 0x71E08558,
    0x3C5CFCAA, 0x7D239CA4, 0x0297D9DD, 0xD7DC2830, 0x4B37802B, 0x7428AB54, 0xAEEE0347, 0x4B3FBB85,
    0x692F2F08, 0x134E578E, 0x36D9E0BF, 0xAE8B5FCF, 0xEDB93ECF, 0x2B27248E, 0x170EB1EF, 0x7DC57FD6,
    0x1E760F16, 0xB1136601, 0x864E1B9B, 0xD7EA7319, 0x3AB871BD, 0xCFA4D76F, 0xE31BD782, 0x0DBEB469,
    0xABB96061, 0x5370F85D, 0xFFB07E37, 0xDA30D0FB, 0xEBC977B6, 0x0B98B40F, 0x3A4D0FE6, 0xDF4FC26B,
    0x159CF22A, 0xC298D6E2, 0x2B78EF6A, 0x61A94AC0, 0xAB561187, 0x14EEA0F0, 0xDF0D4164, 0x19AF70EE,
]


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _rotl32(value: int, shift: int) -> int:
    shift &= 31
    return _u32((value << shift) | (value >> ((32 - shift) & 31)))


def _rotr32(value: int, shift: int) -> int:
    shift &= 31
    return _u32((value >> shift) | (value << ((32 - shift) & 31)))


def _s0(value: int) -> int:
    return SBOX[value & 0xFF]


def _s1(value: int) -> int:
    return SBOX[(value & 0xFF) + 256]


def _s(value: int) -> int:
    return SBOX[value & 0x1FF]


def _get_user_key_le(key: bytes, out_words: int) -> list[int]:
    out = [0] * out_words
    for i, byte in enumerate(key):
        word = i // 4
        shift = (i % 4) * 8
        if word < out_words:
            out[word] |= byte << shift
    return out


def _set_key(key: bytes) -> list[int]:
    t = _get_user_key_le(key, 15)
    t[len(key) // 4] = len(key) // 4
    k = [0] * 40
    for j in range(4):
        for i in range(15):
            x = t[(i + 8) % 15] ^ t[(i + 13) % 15]
            t[i] = _u32(t[i] ^ _rotl32(x, 3) ^ (4 * i + j))
        for _ in range(4):
            for i in range(15):
                t[i] = _rotl32(_u32(t[i] + _s(t[(i + 14) % 15])), 9)
        for i in range(10):
            k[10 * j + i] = t[(4 * i) % 15]
    for i in range(5, 37, 2):
        w = k[i] | 3
        m = (~w ^ (w << 1)) & (~w ^ (w >> 1)) & 0x7FFFFFFE
        m &= m >> 1
        m &= m >> 2
        m &= m >> 4
        m |= m << 1
        m |= m << 2
        m |= m << 4
        m &= 0x7FFFFFFC
        w ^= _rotl32(SBOX[265 + (k[i] & 3)], k[i - 1]) & m
        k[i] = _u32(w)
    return k


def _encrypt_block(block: bytes, key_schedule: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "little")
    b = int.from_bytes(block[4:8], "little")
    c = int.from_bytes(block[8:12], "little")
    d = int.from_bytes(block[12:16], "little")

    a = _u32(a + key_schedule[0])
    b = _u32(b + key_schedule[1])
    c = _u32(c + key_schedule[2])
    d = _u32(d + key_schedule[3])

    for i in range(8):
        b = _u32((b ^ _s0(a)) + _s1(a >> 8))
        c = _u32(c + _s0(a >> 16))
        a = _rotr32(a, 24)
        d ^= _s1(a)
        d = _u32(d)
        if i % 4 == 0:
            a = _u32(a + d)
        if i % 4 == 1:
            a = _u32(a + b)
        a, b, c, d = b, c, d, a

    for i in range(16):
        t = _rotl32(a, 13)
        r = _rotl32(_u32(t * key_schedule[2 * i + 5]), 10)
        m = _u32(a + key_schedule[2 * i + 4])
        l = _rotl32(_s(m) ^ _rotr32(r, 5) ^ r, r)
        c = _u32(c + _rotl32(m, _rotr32(r, 5)))
        if i < 8:
            b = _u32(b + l)
            d ^= r
        else:
            d = _u32(d + l)
            b ^= r
        b = _u32(b)
        d = _u32(d)
        a, b, c, d = b, c, d, t

    for i in range(8):
        if i % 4 == 2:
            a = _u32(a - d)
        if i % 4 == 3:
            a = _u32(a - b)
        b ^= _s1(a)
        b = _u32(b)
        c = _u32(c - _s0(a >> 24))
        t = _rotl32(a, 24)
        d = _u32((d - _s1(a >> 16)) ^ _s0(t))
        a, b, c, d = b, c, d, t

    a = _u32(a - key_schedule[36])
    b = _u32(b - key_schedule[37])
    c = _u32(c - key_schedule[38])
    d = _u32(d - key_schedule[39])
    return (
        a.to_bytes(4, "little")
        + b.to_bytes(4, "little")
        + c.to_bytes(4, "little")
        + d.to_bytes(4, "little")
    )


def _decrypt_block(block: bytes, key_schedule: list[int]) -> bytes:
    d = int.from_bytes(block[0:4], "little")
    c = int.from_bytes(block[4:8], "little")
    b = int.from_bytes(block[8:12], "little")
    a = int.from_bytes(block[12:16], "little")

    d = _u32(d + key_schedule[36])
    c = _u32(c + key_schedule[37])
    b = _u32(b + key_schedule[38])
    a = _u32(a + key_schedule[39])

    for i in range(8):
        b = _u32((b ^ _s0(a)) + _s1(a >> 8))
        c = _u32(c + _s0(a >> 16))
        a = _rotr32(a, 24)
        d ^= _s1(a)
        d = _u32(d)
        if i % 4 == 0:
            a = _u32(a + d)
        if i % 4 == 1:
            a = _u32(a + b)
        a, b, c, d = b, c, d, a

    for i in range(16):
        t = _rotr32(a, 13)
        r = _rotl32(_u32(a * key_schedule[35 - 2 * i]), 10)
        m = _u32(t + key_schedule[34 - 2 * i])
        l = _rotl32(_s(m) ^ _rotr32(r, 5) ^ r, r)
        c = _u32(c - _rotl32(m, _rotr32(r, 5)))
        if i < 8:
            b = _u32(b - l)
            d ^= r
        else:
            d = _u32(d - l)
            b ^= r
        b = _u32(b)
        d = _u32(d)
        a, b, c, d = b, c, d, t

    for i in range(8):
        if i % 4 == 2:
            a = _u32(a - d)
        if i % 4 == 3:
            a = _u32(a - b)
        b ^= _s1(a)
        b = _u32(b)
        c = _u32(c - _s0(a >> 24))
        t = _rotl32(a, 24)
        d = _u32((d - _s1(a >> 16)) ^ _s0(t))
        a, b, c, d = b, c, d, t

    d = _u32(d - key_schedule[0])
    c = _u32(c - key_schedule[1])
    b = _u32(b - key_schedule[2])
    a = _u32(a - key_schedule[3])
    return (
        d.to_bytes(4, "little")
        + c.to_bytes(4, "little")
        + b.to_bytes(4, "little")
        + a.to_bytes(4, "little")
    )


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if not (MIN_KEY_SIZE <= len(key) <= MAX_KEY_SIZE) or (len(key) % 4) != 0:
        raise ValueError("invalid key length")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    key_schedule = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, key_schedule)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if not (MIN_KEY_SIZE <= len(key) <= MAX_KEY_SIZE) or (len(key) % 4) != 0:
        raise ValueError("invalid key length")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    key_schedule = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, key_schedule)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
