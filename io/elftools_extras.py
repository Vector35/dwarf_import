# Copyright(c) 2021-2023 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and / or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

from elftools.dwarf.descriptions import describe_reg_name as elftools_describe_reg_name

# https://developer.arm.com/documentation/ihi0040/c/?lang=en#dwarf-register-names
_REG_NAMES_ARM = [
    # 0-15
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    # 16-63
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    # 64-95
    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
    's8', 's9', 's10', 's11', 's12', 's13', 's14', 's15',
    's16', 's17', 's18', 's19', 's20', 's21', 's22', 's23',
    's24', 's25', 's26', 's27', 's28', 's29', 's30', 's31',
    # 96-103
    'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',
    # 104-11
    'ACC0', 'ACC1', 'ACC2', 'ACC3', 'ACC4', 'ACC5', 'ACC6', 'ACC7',
    # 112-127
    'wR0', 'wR1', 'wR2', 'wR3', 'wR4', 'wR5', 'wR6', 'wR7',
    'wR8', 'wR9', 'wR10', 'wR11', 'wR12', 'wR13', 'wR14', 'wR15',
    # 128
    'SPSR',
    # 129
    'SPSR_FIQ',
    # 130
    'SPSR_IRQ',
    # 131
    'SPSR_ABT',
    # 132
    'SPSR_UND',
    # 133
    'SPSR_SVC',
    # 134-143
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>',
    # 144-150
    'R8_USR', 'R9_USR', 'R10_USR', 'R11_USR', 'R12_USR', 'R13_USR', 'R14_USR',
    # 151-157
    'R8_FIQ', 'R9_FIQ', 'R10_FIQ', 'R11_FIQ', 'R12_FIQ', 'R13_FIQ', 'R14_FIQ',
    # 158-159
    'R13_IRQ', 'R14_IRQ',
    # 160-161
    'R13_ABT', 'R14_ABT',
    # 162-163
    'R13_UND', 'R14_UND',
    # 164-165
    'R13_SVC', 'R14_SVC',
    # 166-191
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>',
    # 192-199
    'wC0', 'wC1', 'wC2', 'wC3', 'wC4', 'wC5', 'wC6', 'wC7',
    # 200-255
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    # 256-287
    'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7',
    'd8', 'd9', 'd10', 'd11', 'd12', 'd13', 'd14', 'd15',
    'd16', 'd17', 'd18', 'd19', 'd20', 'd21', 'd22', 'd23',
    'd24', 'd25', 'd26', 'd27', 'd28', 'd29', 'd30', 'd31',
    # 288-319
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>'
    # 320-8191 None
    # 8192-16383 Vendor co-processor
]

# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/MIPS/data/languages/mips.dwarf
_REG_NAMES_MIPS = [
    # 0-32
    '$zero', '$at', '$v0', '$v1',
    '$a0', '$a1', '$a2', '$a3',
    '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7',
    '$s0', '$s1', '$s2', '$s3', '$s4', '$s5', '$s6', '$s7',
    '$t8', '$t9',
    '$k0', '$k1',
    '$gp', '$sp',
    '$fp',
    '$ra',
    # 32-64
    '$f0', '$f1', '$f2', '$f3', '$f4', '$f5', '$f6', '$f7',
    '$f8', '$f9', '$f10', '$f11', '$f12', '$f13', '$f14', '$f15',
    '$f16', '$f17', '$f18', '$f19', '$f20', '$f21', '$f22', '$f23',
    '$f24', '$f25', '$f26', '$f27', '$f28', '$f29', '$f30', '$f31'
    #
    '<none> (64)', '<none> (65)', '<none> (66)', '<none> (67)',
    '<none> (68)', '<none> (69)', '<none> (70)', '<none> (71)',
]

# http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf
# https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html#DW-REG
_REG_NAMES_POWERPC = [
    # 0-31
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23',
    'r24', 'r25', 'r26', 'r27', 'r28', 'r29', 'r30', 'r31',
    # 32-63
    'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',
    'f8', 'f9', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15',
    'f16', 'f17', 'f18', 'f19', 'f20', 'f21', 'f22', 'f23',
    'f24', 'f25', 'f26', 'f27', 'f28', 'f29', 'f30', 'f31',
    # 64, 65
    'CR', 'FPSCR',
    # 66-99
    'MSR', '<none> (67)', '<none> (68)', '<none> (69)',
    'SR0', 'SR1', 'SR2', 'SR3', 'SR4', 'SR5', 'SR6', 'SR7',
    'SR8', 'SR9', 'SR10', 'SR11', 'SR12', 'SR13', 'SR14', 'SR15',
    '<none> (86)', '<none> (87)', '<none> (88)', '<none> (89)',
    '<none> (90)', '<none> (91)', '<none> (92)', '<none> (93)',
    '<none> (94)', '<none> (95)', '<none> (96)', '<none> (97)',
    '<none> (98)', '<none> (99)',
    # 100, 101
    'MQ', 'XER',
    # 102, 103
    '<none>', '<none>',
    # 104, 105
    'RTCU', 'RTCL',
    # 106, 107
    '<none>', '<none>',
    # 108, 109
    'LR', 'CTR'
]

# https://developer.arm.com/documentation/ihi0057/e/?lang=en#dwarf-register-names
_REG_NAMES_AArch64 = [
    # 0-31
    'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
    'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp',

    # 32, 33, 34
    '<reserved>', 'elr_mode', 'ra_sign_state',

    # 35, 36
    '<none> (35)', '<none> (36)',

    # 37-45
    '<none> (37)', '<none> (38)', '<none> (39)', '<none> (40)',
    '<none> (41)', '<none> (42)', '<none> (43)', '<none> (44)',
    '<none> (45)',

    # 46, 47
    'vg', 'ffr',

    # 48-63
    'p0', 'p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7',
    'p8', 'p9', 'p10', 'p11', 'p12', 'p13', 'p14', 'p15',

    # 64-95
    'v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7',
    'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15',
    'v16', 'v17', 'v18', 'v19', 'v20', 'v21', 'v22', 'v23',
    'v24', 'v25', 'v26', 'v27', 'v28', 'v29', 'v30', 'v31',

    # 96-127
    'z0', 'z1', 'z2', 'z3', 'z4', 'z5', 'z6', 'z7',
    'z8', 'z9', 'z10', 'z11', 'z12', 'z13', 'z14', 'z15',
    'z16', 'z17', 'z18', 'z19', 'z20', 'z21', 'z22', 'z23',
    'z24', 'z25', 'z26', 'z27', 'z28', 'z29', 'z30', 'z31'
]

_REG_NAMES_x64 = [
    'rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rip', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6',
    'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14',
    'xmm15', 'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6',
    'st7', 'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6',
    'mm7', 'rflags', 'es', 'cs', 'ss', 'ds', 'fs', 'gs',
    '<none>', '<none>',
    'fs.base', 'gs.base',
    '<none>', '<none>',
    'tr',
    'ldtr',
    'mxcsr',
    'fcw',
    'fsw',
    'xmm16', 'xmm17', 'xmm18', 'xmm19', 'xmm20', 'xmm21', 'xmm22', 'xmm23', 'xmm24', 'xmm25', 'xmm26', 'xmm27', 'xmm28', 'xmm29', 'xmm30', 'xmm31',
]


def describe_reg_name(regnum, machine_arch=None, default=True):
    assert machine_arch in ['AArch64', 'ARM', 'x86', 'x64', 'MIPS', 'PowerPC'], 'unrecognized: %s' % machine_arch

    if machine_arch == 'x64':
        return _REG_NAMES_x64[regnum]
    if machine_arch == 'ARM':
        return _REG_NAMES_ARM[regnum]
    if machine_arch == 'MIPS':
        return _REG_NAMES_MIPS[regnum]
    if machine_arch == 'PowerPC':
        return _REG_NAMES_POWERPC[regnum]
    if machine_arch == 'AArch64':
        return _REG_NAMES_AArch64[regnum]
    return elftools_describe_reg_name(regnum, machine_arch, default)
