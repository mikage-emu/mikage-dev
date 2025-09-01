#include "thumb.hpp"

#include <framework/exceptions.hpp>

namespace ARM {

DecodedThumbInstr DecodeThumb(ARM::ThumbInstr instr) {
    if (instr.opcode_upper5 == 0b00000) {
        // LSL (1) - Logical Shift Left
        ARM::ARMInstr arm_instr;
        arm_instr.raw = ((0b1110'0001'1011'0000ul) << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5 } << 7)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b00010) {
        // ASR (1) - Arithmetic Shift Right
        ARM::ARMInstr arm_instr;
//        arm_instr.raw = (0b1110'0001'1011'0000ul << 16)
//                        | (uint32_t { instr.idx_rd_low } << 12)
//                        | (uint32_t { instr.immed_mid_5 } << 7)
//                        | (0b100ul << 3)
//                        | instr.idx_rm;
        arm_instr.raw = (0b1110'0001'1011'0000ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5 } << 7)
                        | (0b100ul << 4)
                        | instr.idx_rm;
//        arm_instr.raw = (0b1110'0001'1011'0000'0000'1111'1010'0000ul); // shift_imm = 31, shift = 1
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0000'00) {
        // AND
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0000'0001ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0001'01) {
        // ADC
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0000'1011ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0001110) {
        // ADD (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0010'1001ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.immed_mid_5_lower3;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b00110) {
        // ADD (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0010'1001ul << 20)
                        | (uint32_t { instr.idx_rd_high } << 16)
                        | (uint32_t { instr.idx_rd_high } << 12)
                        | instr.immed_low_8;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0001100) {
        // ADD (3)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0000'1001ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper8 == 0b01000100) {
        // ADD (4)
        ARM::ARMInstr arm_instr;
        auto idx_rd = uint32_t { instr.idx_rd_low } | (uint32_t { instr.idx_rd_upperbit } << 3);
        auto idx_rm = uint32_t { instr.idx_rm } | (uint32_t { instr.idx_rm_upperbit } << 3);
        arm_instr.raw = (0b1110'0000'1000ul << 20)
                        | (idx_rd << 16)
                        | (idx_rd << 12)
                        | idx_rm;
        auto ret = DecodedThumbInstr { arm_instr }.SetMayReadPC();
        if (idx_rd == 15) {
            ret.SetMayModifyPC();
        }
        return ret;
//    } else if (instr.opcode_upper5 == 0b10100) {
//        // ADD (5)
//        ARM::ARMInstr arm_instr;
//        arm_instr.raw = (0b1110'0010'1000'1111ul << 16)
//                        | (uint32_t { instr.idx_rd_high } << 12)
//                        | (0b1111ul << 8)
//                        | instr.immed_low_8;
//        return DecodedThumbInstr { arm_instr }.SetMayReadPC();
    } else if (instr.opcode_upper5 == 0b10101) {
        // ADD (6)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0010'1000'1101ul << 16)
                        | (uint32_t { instr.idx_rd_high } << 12)
                        | (0b1111ul << 8)
                        | instr.immed_low_8;
        return { arm_instr };
    } else if (instr.opcode_upper9 == 0b1011'0000'0) {
        // ADD (7)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110001010001101110111110ul << 7)
                        | instr.immed_low_7;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0011'10) {
        // BIC
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b111000011101ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        |  instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0010'00) {
        // TST
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b111000010001ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        |  instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0001'111) {
        // SUB (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b111000100101ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.immed_mid_5_lower3;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b00111) {
        // SUB (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0010'0101ul << 20)
                        | (uint32_t { instr.idx_rd_high } << 16)
                        | (uint32_t { instr.idx_rd_high } << 12)
                        | instr.immed_low_8;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0001'101) {
        // SUB (3)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0000'0101ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper9 == 0b1011'0000'1) {
        // SUB (4)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0010'0100'1101'1101'1111'0ul << 7)
                        | instr.immed_low_7;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0001'10) {
        // SBC
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0000'1101ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0011'00) {
        // ORR
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1001ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0000'01) {
        // EOR
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0000'0011ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b00100) {
        // MOV (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0011'1011'0000ul << 16)
                        | (uint32_t { instr.idx_rd_high } << 12)
                        | instr.immed_low_8;
        return { arm_instr };
    } else if (instr.opcode_upper8 == 0b0100'0110) {
        // MOV (3)
        ARM::ARMInstr arm_instr;
        auto idx_rd = uint32_t { instr.idx_rd_low } | (uint32_t { instr.idx_rd_upperbit } << 3);
        auto idx_rm = uint32_t { instr.idx_rm } | (uint32_t { instr.idx_rm_upperbit } << 3);
        arm_instr.raw = (0b1110'0001'1010ul << 20)
                        | (idx_rd << 12)
                        | idx_rm;
        auto ret = DecodedThumbInstr { arm_instr }.SetMayReadPC();
        if (idx_rd == 15) {
            ret.SetMayModifyPC();
        }
        return ret;
    } else if (instr.opcode_upper10 == 0b0100'0011'11) {
        // MVN
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1111'0000ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b00000) {
        // LSL (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1011'0000ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5 } << 7)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0000'10) {
        // LSL (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1011'0000ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.idx_rm } << 8)
                        | 0b1'0000
                        | instr.idx_rd_low;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b00001) {
        // LSR (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1011'0000ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5 } << 7)
                        | 0b10'0000
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0000'11) {
        // LSR (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1011'0000ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.idx_rm } << 8)
                        | 0b11'0000
                        | instr.idx_rd_low;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0010'01) {
        // NEG
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0010'0111ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12);
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0011'01) {
        // MUL
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0000'0001ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rd_low } << 8)
                        | (0b1001ul << 4)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b1011'1010'00) {
        // REV
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0110'1011'1111ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b1111'0011ul << 4)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0001'11) {
        // ROR
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1011'0000ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.idx_rm } << 8)
                        | (0b0111ul << 4)
                        | instr.idx_rd_low;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b1011'0010'01) {
        // SXTB
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0110'1010'1111ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b0111ul << 4)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b1011'0010'00) {
        // SXTH
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0110'1011'1111ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b0111ul << 4)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b1011'0010'10) {
        // UXTH
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0110'1111'1111ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b0111ul << 4)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b1011'0010'11) {
        // UXTB
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0110'1110'1111ul << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b0111ul << 4)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b11001) {
        // LDMIA
        ARM::ARMInstr arm_instr;
        uint32_t has_rd = (instr.register_list >> instr.idx_rd_high) & 1;
        arm_instr.raw = (0b1110'1000'1001ul << 20)
                        | (uint32_t { !has_rd } << 21)
                        | (uint32_t { instr.idx_rd_high } << 16)
                        | instr.register_list;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b01101) {
        // LDR (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0101'1001ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5 } << 2);
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101'100) {
        // LDR (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0111'1001ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b10011) {
        // LDR (4)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0101'1001'1101ul << 16)
                        | (uint32_t { instr.idx_rd_high } << 12)
                        | (uint32_t { instr.immed_low_8 } << 2);
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b01111) {
        // LDRB (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0101'1101ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.immed_mid_5;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101110) {
        // LDRB (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0111'1101ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101011) {
        // LDRSB
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1001ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b1101ul << 4)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101111) {
        // LDRSH
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1001ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b1111ul << 4)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b10001) {
        // LDRH (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1101ul<< 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5_upper2 } << 8)
                        | (0b1011ul << 4)
                        | (uint32_t { instr.immed_mid_5_lower3 } << 1);
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101'101) {
        // LDRH (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1001ul<< 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b1011ul << 4)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b00101) {
        // CMP (1) - Compare
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0011'0101ul << 20)
                        | (uint32_t { instr.idx_rd_high } << 16)
                        | (instr.immed_low_8);
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b0100'0010'10) {
        // CMP (2) - Compare
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b111000010101ul << 20)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper8 == 0b0100'0101) {
        // CMP (3) - Compare
        ARM::ARMInstr arm_instr;
        if (!instr.idx_rd_upperbit && !instr.idx_rm_upperbit) {
            throw Mikage::Exceptions::Invalid("Unpredictable configuration");
        }
        if (instr.idx_rm_upperbit && instr.idx_rm == 7) {
            throw Mikage::Exceptions::Invalid("Unpredictable configuration");
        }
        if (instr.idx_rd_upperbit && instr.idx_rd_low == 7) {
            throw Mikage::Exceptions::NotImplemented("Cannot use PC for this instruction, yet");
        }
        arm_instr.raw = (0b111000010101ul << 20)
                        | (uint32_t { instr.idx_rd_upperbit } << 19)
                        | (uint32_t { instr.idx_rd_low } << 16)
                        | (uint32_t { instr.idx_rm_upperbit } << 3)
                        | instr.idx_rm;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b11000) {
        // STMIA
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'1000'1010ul << 20)
                        | (uint32_t { instr.idx_rd_high } << 16)
                        | instr.register_list;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b01100) {
        // STR (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0101'1000ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5 } << 2);
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101000) {
        // STR (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0111'1000ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b10010) {
        // STR (3)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0101'1000'1101ul << 16)
                        | (uint32_t { instr.idx_rd_high } << 12)
                        | (uint32_t { instr.immed_low_8 } << 2);
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b01110) {
        // STRB (1)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0101'1100ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.immed_mid_5;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101'010) {
        // STRB (2)
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0111'1100ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper5 == 0b10000) {
        // STRH (1) - Store Register Halfword
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1100ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (uint32_t { instr.immed_mid_5_upper2 } << 8)
                        | (0b1011 << 4)
                        | (uint32_t { instr.immed_mid_5_lower3 } << 1);
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b0101001) {
        // STRH (2) - Store Register Halfword
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'0001'1000ul << 20)
                        | (uint32_t { instr.idx_rm } << 16)
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | (0b1011 << 4)
                        | instr.idx_rn;
        return { arm_instr };
    } else if (instr.opcode_upper7 == 0b1011'010) {
        // PUSH - Push Multiple Registers
        ARM::ARMInstr arm_instr;
        arm_instr.raw = (0b1110'1001'0010'1101ul << 16)
                        | ((uint32_t { instr.raw } & 0x100) << 6) // bit8 denotes whether to push LR
                        | instr.register_list;
        return { arm_instr };
    } else if (instr.opcode_upper10 == 0b1011101001) {
        // REV16
        ARM::ARMInstr arm_instr;
        arm_instr.raw = 0b1110'0110'1011'1111'0000'1111'1011'0000ul
                        | (uint32_t { instr.idx_rd_low } << 12)
                        | instr.idx_rm;
        return { arm_instr };
    } else {
        // Instruction has no ARM equivalent, let the caller handle it manually
        return { };
    }
}

} // namespace ARM
