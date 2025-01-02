// TODO: Port https://github.com/citra-emu/citra/pull/6844
#include "context.h"
#include "shader.hpp"
#include "shader_analysis.hpp"
#include "shader_microcode.hpp"
#include "shader_microcode_handlers.hpp"

#include <framework/exceptions.hpp>
#include <framework/meta_tools.hpp>

#include <boost/container/static_vector.hpp>

#include <range/v3/algorithm/copy.hpp>
#include <range/v3/algorithm/fill.hpp>
#include <range/v3/view/indices.hpp>
#include <range/v3/view/indirect.hpp>
#include <range/v3/view/iota.hpp>
#include <range/v3/view/take.hpp>

#include <tracy/Tracy.hpp>
#include <tracy/TracyC.h>

#include <bitset>

#include <iostream> // TODO: Drop

using nihstro::OpCode;
using nihstro::Instruction;
using nihstro::RegisterType;
using nihstro::SourceRegister;
using nihstro::SwizzlePattern;

template<typename T>
constexpr inline int popcount(T t) {
#ifdef __cpp_lib_bitops
    return std::popcount(t);
#else
    return __builtin_popcount(t);
#endif
}

namespace Pica::VertexShader {

static void ValidateOutputConfiguration(const Pica::Regs& registers) {
    if (registers.vs_output_attributes_minus_1 != registers.vs_output_attributes_minus_1_copy) {
        throw Mikage::Exceptions::NotImplemented("Inconsistent VS output attribute counts");
    }
    auto active_shader_regs = static_cast<unsigned>(popcount(registers.vs_output_register_mask.mask()()));
    if (registers.vs_output_attributes_minus_1 >= active_shader_regs) {
        throw Mikage::Exceptions::Invalid(  "Requested {} output attributes, but only {} were output by the shader",
                                            registers.vs_output_attributes_minus_1 + 1,
                                            active_shader_regs);
    }

    // TODO: This may be violated currently due to missing implementation of geometry shaders
//    if (registers.shader_num_output_attributes < active_shader_regs) {
//        throw Mikage::Exceptions::Invalid("Shader output register count is lower than the number of attributes it's supposed to output");
//    }
}

std::string DisassembleMicroOp(const MicroOp& op) {
    const char* indent = ""; // TODO

    auto format_binary_op = [](const char* name, const MicroOp& micro_op) {
        auto lookup_component = [](SwizzlePattern::Selector sel) {
            const char table[] = { 'x', 'y', 'z', 'w' };
            return table[Meta::to_underlying(sel)];
        };
        auto swizzle = SwizzlePattern { micro_op.arg2 };

        char dest_mask[] = "xyzw\0";
        for (auto i : ranges::views::iota(0, 4)) {
            if (!swizzle.DestComponentEnabled(i)) {
                dest_mask[i] = '_';
            }
        }

        return fmt::format( "{} dest.{}, src1.{}{}{}{}, src2.{}{}{}{}", name, dest_mask,
                            lookup_component(swizzle.GetSelectorSrc1(0)), lookup_component(swizzle.GetSelectorSrc1(1)),
                            lookup_component(swizzle.GetSelectorSrc1(2)), lookup_component(swizzle.GetSelectorSrc1(3)),
                            lookup_component(swizzle.GetSelectorSrc2(0)), lookup_component(swizzle.GetSelectorSrc2(1)),
                            lookup_component(swizzle.GetSelectorSrc2(2)), lookup_component(swizzle.GetSelectorSrc2(3)));
    };

    using Type = MicroOpType;
    switch (op.type) {
    case Type::Call:
        return fmt::format("{}Call             target={:#05x}    num_instrs={:#x} return={:#x}", indent, op.arg0, op.arg1, op.arg2);

    case Type::EnterLoop:
        // TODO: Read parameters set up by the preceding PrepareLoop micro op
        return fmt::format("{}EnterLoop        target={:#05x}    num_instrs={:#x} return={:#x}", indent, op.arg0, op.arg1, op.arg2);

    case Type::PopCallStack:
        return fmt::format("{}PopCallStack     current_offset={:#05x} (pica: {:#x})", indent, op.arg0, 4 * op.arg1);

    case Type::PredicateNext:
        return fmt::format("{}PredicateNext    reg={}", indent, op.arg0);

    case Type::Goto:
        return fmt::format("{}Goto             target={:#05x} (pica: {:#x})", indent, op.arg0, 4 * op.arg1);

    case Type::EvalConditionOr:
        return fmt::format("{}EvalCondition    refx={} OR  refy={}", indent, op.arg0, op.arg1);

    case Type::EvalConditionAnd:
        return fmt::format("{}EvalCondition    refx={} AND refy={}", indent, op.arg0, op.arg1);

    case Type::EvalConditionJustX:
        return fmt::format("{}EvalCondition    refx={}", indent, op.arg0);

    case Type::EvalConditionJustY:
        return fmt::format("{}EvalCondition    refy={}", indent, op.arg1);

    case Type::End:
        return "END";

    case Type::Add:
        return format_binary_op("ADD ", op);

    case Type::Mul:
        return format_binary_op("MUL ", op);

    case Type::Max:
        return format_binary_op("MAX ", op);

    case Type::Min:
        return format_binary_op("MIN ", op);

    case Type::Dot3:
        return format_binary_op("DOT3", op);

    case Type::Dot4:
        return format_binary_op("DOT4", op);

    case Type::Mov:
        return format_binary_op("MOV ", op);

    case Type::Floor:
        return format_binary_op("FLR ", op);

    case Type::MovToAddressReg:
        return format_binary_op("MOVA", op);

    case Type::Rcp:
        return format_binary_op("RCP ", op);

    case Type::Rsq:
        return format_binary_op("RSQ ", op);

    default:
        // TODO: CMP, etc
        return fmt::format("{}UNKNOWN          {:#x} {:#x} {:#x}", indent, op.arg0, op.arg1, op.arg2);
    }
}

struct MicroCodeRecompilerEngine : ShaderEngine {
    MicroCodeRecompilerEngine(MicroCode);

    void Reset(const Regs::VSInputRegisterMap&, InputVertex&, uint32_t num_attributes) override;

    void UpdateUniforms(const std::array<Math::Vec4<float24>, 96>&) override;

    OutputVertex Run(Context& pica_context, uint32_t entry) override;

    std::array<Math::Vec4<float24>*, 16> input_register_table;

    // Only used to catch writes to unmapped input registers
    Math::Vec4<float24> dummy_register;

    ShaderCodeOffset entry_point;

    uint32_t num_input_attributes;

    MicroCode micro_code;

    // TODO: Page-align?
    RecompilerRuntimeContext context;

    std::unique_ptr<ShaderEngine> interpreter;
};

/**
 * Some micro code take micro code offsets, but only PICA200 shader offsets are
 * known upon generating them, so we store a ShaderCodeOffset as a
 * MicroOpOffset and later patch it up manually
 */
template<typename T>
using CoerceShaderOffsets = std::conditional_t<std::is_same_v<T, ShaderCodeOffset>, MicroOpOffset, T>;

// TODO: Discard Handler argument
template<typename T1 = uint32_t, typename T2 = uint32_t, typename T3 = uint32_t>
static void AddMicroOp(MicroCode& code, MicroOpType type, T1 arg0 = {}, T2 arg1 = {}, T3 arg2 = {}) {
//    static_assert(std::is_invocable_v<  Handler, RecompilerRuntimeContext&,
//                                        CoerceShaderOffsets<T1>, CoerceShaderOffsets<T2>,
//                                        CoerceShaderOffsets<T3>>);

    auto to_u32 = [](auto arg) noexcept -> uint32_t {
        using Type = decltype(arg);
        if constexpr (std::is_same_v<Type, MicroOpOffset>) {
            return arg.value;
        } else if constexpr (std::is_same_v<Type, ShaderCodeOffset>) {
            return arg.value;
        } else if constexpr (std::is_same_v<Type, SwizzlePattern>) {
            return arg.hex;
        } else {
            return arg;
        }
    };

    code.ops.push_back(MicroOp { { type }, to_u32(arg0), to_u32(arg1), to_u32(arg2) });
}

// Returns the index into state.conditional_code from which to read the condition result
static uint32_t EmitMicroOpEvalCondition(MicroCode& code, Instruction::FlowControlType flow_control) {
    using namespace MicroOps;
    using Op = Instruction::FlowControlType::Op;
    if (flow_control.op == Op::JustX && flow_control.refx) {
        return 0;
    } else if (flow_control.op == Op::JustY && flow_control.refy) {
        return 1;
    } else {
        auto micro_op_type = Meta::next_enum(MicroOpType::EvalCondition, Meta::to_underlying(flow_control.op.Value()));
        AddMicroOp(code, micro_op_type, flow_control.refx.Value(), flow_control.refy.Value());
        return 2;
    }
}

template<auto F>
static void MicroOpTypeErased(RecompilerRuntimeContext& engine, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    F(engine, { arg1 }, { arg2 }, { arg3 });
}

// TODO: Get rid of this
std::string global_vertex_shader_code_todo;

template<typename InstrRng, typename SwizzleRng>
static MicroCode RecompileToMicroCodeInternal(
        const AnalyzedProgram& program,
        const InstrRng& shader_memory,
        const SwizzleRng& swizzle_data,
        std::bitset<16> bool_uniforms,
        const decltype(Regs::vs_int_uniforms)& int_uniforms) {
    using OpType = MicroOpType;

    MicroCode code;

    for (auto& block : program.blocks) {
        if (code.block_offsets.count(block.first)) {
            throw std::runtime_error(fmt::format("Already processed block at pica byte offset {:#x}", 4 * block.first.value));
        }

        // TODO: Can we get rid of this line? I think it's needed for empty blocks, which we generate for exit points on instruction offsets that are never executed (e.g. end of a function)
        //       We really should only need to check once per block rather than once per instruction!
        code.block_offsets[block.first] = MicroOpOffset { static_cast<uint32_t>(code.ops.size()) };

// TODO: Check SuccessionVia instead to link blocks together
bool dont_link_to_next = false;

        if (block.second.length == 0xffffffff) {
            throw std::runtime_error(fmt::format("Unknown block length for block starting at {:#x}", 4 * block.first.value));
        }

        const auto block_end = block.first.IncrementedBy(block.second.length);
        for (auto instr_offset = block.first; !(instr_offset == block_end); instr_offset = instr_offset.GetNext()) {
//            AddMicroOp(code, MicroOpType::Trace, MicroOpOffset { static_cast<uint32_t>(code.ops.size()) }, instr_offset /* Debugging only */);

            const Instruction instr = instr_offset.ReadFrom(shader_memory);
            auto is_control_flow = [](Instruction instr) {
                auto opcode = instr.opcode.Value().GetInfo().type;
                return (opcode != OpCode::Type::Arithmetic && opcode != OpCode::Type::MultiplyAdd);
            };

            if (!is_control_flow(instr)) {
                auto last_instr = instr_offset;
//                for (auto instr : ranges::views::iota(instr_offset, block_end)) {
//                    if (is_control_flow(instr.ReadFrom(shader_memory))) {
//                        break;
//                    }
//                    last_instr = instr;
//                }

                bool is_inverted = 0 != (instr.opcode.Value().GetInfo().subtype & OpCode::Info::SrcInversed);
                // TODO: Actually, is_inverted might not be supported properly currently...
                uint32_t src1_reg_index = instr.common.GetSrc1(is_inverted);
                uint32_t src2_reg_index = instr.common.GetSrc2(is_inverted);
                uint32_t src1_addr_offset_index = (is_inverted ? 0 : instr.common.address_register_index.Value());
                uint32_t src2_addr_offset_index = (is_inverted ? instr.common.address_register_index.Value() : 0);
                if (src2_addr_offset_index) {
//                    throw Mikage::Exceptions::NotImplemented("Address offset for src2 not supported yet");
                }
                uint32_t src_info = src1_reg_index | (src2_reg_index << 16u) | (src1_addr_offset_index << 8u) | (src2_addr_offset_index << 24u);
                // Relocate output registers to 0x80 to avoid index collision with input registers
                auto dst_reg = (instr.common.dest.Value() < 0x10) ? (instr.common.dest.Value() + 0x80) : static_cast<uint32_t>(instr.common.dest.Value());

                const bool is_mad = (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MAD);
                auto swizzle = SwizzlePattern { swizzle_data[is_mad ? instr.mad.operand_desc_id : instr.common.operand_desc_id] };
//                auto num_dest_components = [](SwizzlePattern swizzle) {
//                    uint32_t ret = 0;
//                    for (auto i : ranges::views::iota(0, 4)) {
//                        ret += swizzle.DestComponentEnabled(i);
//                    }
//                    return ret;
//                };
//                auto get_scalar_component = [](SwizzlePattern swizzle) -> std::optional<uint32_t> {
//                    if (swizzle.dest_mask == 1) {
//                        return 3;
//                    } else if (swizzle.dest_mask == 2) {
//                        return 2;
//                    } else if (swizzle.dest_mask == 4) {
//                        return 1;
//                    } else if (swizzle.dest_mask == 8) {
//                        return 0;
//                    } else {
//                        return std::nullopt;
//                    }
//                };

                if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::ADD) {
                    AddMicroOp(code, OpType::Add, src_info, dst_reg, swizzle);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MUL) {
                    AddMicroOp(code, OpType::Mul, src_info, dst_reg, swizzle);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MAX) {
                    AddMicroOp(code, OpType::Max, src_info, dst_reg, swizzle);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MIN) {
                    AddMicroOp(code, OpType::Min, src_info, dst_reg, swizzle);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::DP3) {
                    AddMicroOp(code, OpType::Dot3, src_info, dst_reg, swizzle);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::DP4) {
                    AddMicroOp(code, OpType::Dot4, src_info, dst_reg, swizzle);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MOV) {
                    AddMicroOp(code, OpType::Mov, src_info, dst_reg, swizzle.hex);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::FLR) {
                    AddMicroOp(code, OpType::Floor, src_info, dst_reg, swizzle.hex);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MOVA) {
                    AddMicroOp(code, OpType::MovToAddressReg, src_info, dst_reg, swizzle.hex);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::CMP) {
                    for (uint32_t i = 0; i < 2; ++i) {
                        auto compare_op = instr.common.compare_op;
                        auto op = (i == 0) ? compare_op.x.Value() : compare_op.y.Value();

                        AddMicroOp( code,
                                    Meta::next_enum(MicroOpType::Compare, Meta::to_underlying(op)),
                                    src_info,
                                    i,
                                    swizzle_data[instr.common.operand_desc_id]);
                    }
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::RCP) {
                    AddMicroOp(code, OpType::Rcp, src_info, dst_reg, swizzle.hex);
                } else if (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::RSQ) {
                    AddMicroOp(code, OpType::Rsq, src_info, dst_reg, swizzle.hex);
                } else if ( instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MAD ||
                            instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MADI) {

                    uint32_t src1_reg_index = instr.mad.GetSrc1(is_inverted);
                    uint32_t src2_reg_index = instr.mad.GetSrc2(is_inverted);
                    uint32_t src3_reg_index = instr.mad.GetSrc3(is_inverted);

                    uint32_t src2_addr_offset_index = (is_inverted ? 0 : instr.mad.address_register_index.Value());
                    uint32_t src3_addr_offset_index = (is_inverted ? instr.mad.address_register_index.Value() : 0);
                    uint32_t src_info = src1_reg_index | (src2_reg_index << 16u) | (src2_addr_offset_index << 8u) | (src3_addr_offset_index << 24u);
                    auto dst_reg = (instr.mad.dest.Value() < 0x10) ? (instr.mad.dest.Value() + 0x80) : static_cast<uint32_t>(instr.mad.dest.Value());
                    dst_reg |= (src3_reg_index << 16);

                    AddMicroOp(code, MicroOpType::Mad, src_info, dst_reg, swizzle);
                } else {
//                    throw Mikage::Exceptions::NotImplemented("Unsupported PICA200 shader instruction: {:#x}", instr.hex);
                }

                // Skip forward
                instr_offset = last_instr;
            } else {
                // Handle each instruction on its own
                switch (instr.opcode.Value()) {
                case OpCode::Id::NOP:
                    break;

                case OpCode::Id::END:
                    AddMicroOp(code, OpType::End);
                    dont_link_to_next = true;
                    break;

                case OpCode::Id::CALLU:
                    if (instr.flow_control.bool_uniform_id == 15) {
//                        throw std::runtime_error("b15 not implemented");
                    }
                    [[fallthrough]];
                case OpCode::Id::CALL:
                case OpCode::Id::CALLC:

                    if (instr.opcode.Value() == OpCode::Id::CALLC) {
                        auto predicate_result = EmitMicroOpEvalCondition(code, instr.flow_control);
                        AddMicroOp( code,
                                    MicroOpType::PredicateNext,
                                    predicate_result,
                                    instr_offset.value /* for debugging only */);
                    }
                    if (instr.opcode.Value() != OpCode::Id::CALLU || bool_uniforms[instr.flow_control.bool_uniform_id]) {
                        auto target = ShaderCodeOffset { instr.flow_control.dest_offset };
                        AddMicroOp( code,
                                    MicroOpType::Call,
                                    target,
                                    instr.flow_control.num_instructions,
                                    instr_offset.GetNext());
                    }

                    dont_link_to_next = (instr.opcode.Value() == OpCode::Id::CALL);
                    break;

                case OpCode::Id::IFC:
                {
                    auto predicate_result = EmitMicroOpEvalCondition(code, instr.flow_control);
                    AddMicroOp( code,
                                MicroOpType::PredicateNext,
                                predicate_result,
                                instr_offset.value /* for debugging only */);

                    auto if_body = instr_offset.GetNext();
                    auto else_body = ShaderCodeOffset { instr.flow_control.dest_offset };

                    // TODO: Instead of manually emitting gotos here, encode the jump targets as PostExecJumps in the individual blocks

                    // Jump to if-body if predicate is true (which will skip past the jump to the else-body)
                    AddMicroOp(code, MicroOpType::Goto, if_body, if_body.value /* debugging only */);

                    // Jump to else-body if predicate is false
                    // If the else-body is empty, this will jump to the end of the conditional
                    AddMicroOp(code, MicroOpType::Goto, else_body, else_body.value /* debugging only */);
                    dont_link_to_next = true;
                    break;
                }

                case OpCode::Id::IFU:
                {
                    if (instr.flow_control.bool_uniform_id == 15) {
//                        throw std::runtime_error("b15 not implemented");
                    }

                    auto else_body = ShaderCodeOffset { instr.flow_control.dest_offset };
                    if (bool_uniforms[instr.flow_control.bool_uniform_id]) {
                        auto if_body = instr_offset.GetNext();
                        AddMicroOp(code, MicroOpType::Goto, if_body, if_body.value /* debugging only */);
                    } else {
                        AddMicroOp(code, MicroOpType::Goto, else_body, else_body.value /* debugging only */);
                    }
                    dont_link_to_next = true;
                    break;
                }

                case OpCode::Id::JMPC:
                {
                    auto predicate_result = EmitMicroOpEvalCondition(code, instr.flow_control);
                    AddMicroOp( code,
                                MicroOpType::Branch,
                                predicate_result,
                                ShaderCodeOffset { instr.flow_control.dest_offset },
                                instr_offset.GetNext());
                    dont_link_to_next = true;
                    break;
                }

                case OpCode::Id::JMPU:
                    if (instr.flow_control.bool_uniform_id == 15) {
//                        throw std::runtime_error("b15 not implemented");
                    }

                    // NOTE: The lowest bit of the num_instructions field indicates an inverted condition for this instruction.
                    // TODO: Add a better-named field alias for this case
                    if (bool_uniforms[instr.flow_control.bool_uniform_id] == !(instr.flow_control.num_instructions & 1)) {
                        AddMicroOp(code, MicroOpType::Goto, ShaderCodeOffset { instr.flow_control.dest_offset }, instr.flow_control.dest_offset /* debugging only */);
                    } else {
                        AddMicroOp(code, MicroOpType::Goto, ShaderCodeOffset { instr_offset.GetNext() }, instr_offset.GetNext().value  /* debugging only */);
                    }
                    dont_link_to_next = true;
                    break;

                case OpCode::Id::BREAKC:
                    // TODO
                    break;

                case OpCode::Id::LOOP:
                {
                    AddMicroOp( code,
                                MicroOpType::PrepareLoop,
                                int_uniforms[instr.flow_control.int_uniform_id].x,
                                int_uniforms[instr.flow_control.int_uniform_id].y,
                                int_uniforms[instr.flow_control.int_uniform_id].z);

                    auto last_loop_instr = ShaderCodeOffset { instr.flow_control.dest_offset };
                    AddMicroOp( code,
                                MicroOpType::EnterLoop,
                                instr_offset.GetNext(),
                                last_loop_instr - instr_offset,
                                last_loop_instr.GetNext());
                    dont_link_to_next = true;
                    break;
                }

                default:
                    throw std::runtime_error(fmt::format("TODO: Unrecognized instruction at offset {:#x}", 4 * instr_offset.value));
                }
            }
        }

        // TODO: Insert asserting micro ops past the last instruction


        if (block.second.post_exec_jump.FromCallStack()) {
            // PICA200 programs don't really have a "return" function:
            // Instead, the return site is declared upon calling the function.
            // This means theoretically this block could pop the call stack
            // conditionally, depending on how it was entered. For now, we
            // assume games never submit shaders that do this.
            //
            // If this assumption were violated, the shader analyzer would
            // register one or more potential successors to this returning
            // block.
            //
            // NOTE: Loops are a special case since they also use the call
            //       stack. For them to be valid, there must be exactly one
            //       successor.
            ValidateContract(   block.second.successors.empty() ||
                                        (block.second.successors.size() == 1 && block.second.successors.begin()->second == AnalyzedProgram::SuccessionVia::LoopEnd));

            AddMicroOp(code, MicroOpType::PopCallStack, MicroOpOffset { static_cast<uint32_t>(code.ops.size()) }, block.first.value /* Debugging only */);
            dont_link_to_next = true; // TODO: is this safe?
        } else if (auto target = block.second.post_exec_jump.GetStaticTarget()) {
            AddMicroOp(code, MicroOpType::Goto, ShaderCodeOffset { *target }, *target /* debugging only */);
            dont_link_to_next = true;
        }


        // Link with the next instruction in case we run off the end of a block
        // TODO: !dont_link_to_next should be equivalent to whether there is a fallthrough successor or not
        if (!dont_link_to_next && block.first != std::prev(program.blocks.end())->first /* TODO: Detect last block more cleanly */) {
            auto next_pica_instr = block.first.IncrementedBy(block.second.length);
            AddMicroOp(code, MicroOpType::Goto, next_pica_instr, block.first.IncrementedBy(block.second.length).value /* debugging only */);
        }

        if (code.ops.empty()) {
            throw std::runtime_error("No micro ops generated for block");
        }
    }

    return code;
}

MicroCode RecompileToMicroCode( const struct AnalyzedProgram& program,
                                const uint32_t* instructions,
                                uint32_t num_instructions,
                                const uint32_t* swizzle_data,
                                uint32_t num_swizzle_slots,
                                std::bitset<16> bool_uniforms,
                                const decltype(Regs::vs_int_uniforms)& int_uniforms) {
    return RecompileToMicroCodeInternal(program,
                                        ranges::views::counted(instructions, num_instructions),
                                        ranges::views::counted(swizzle_data, num_swizzle_slots),
                                        bool_uniforms,
                                        int_uniforms);
}

MicroCodeRecompilerEngine::MicroCodeRecompilerEngine(MicroCode micro_code_)
        : ShaderEngine(true/*false*/), micro_code(std::move(micro_code_)) {

    // Populate micro op handlers

    using namespace MicroOps;
    using EvalOp = Instruction::FlowControlType::Op;

    auto micro_op_offset = MicroOpOffset { 0 }.GetPrevious();
    for (auto& micro_op : micro_code.ops) {
        micro_op_offset.GetNext();

        using Type = MicroOpType;

        switch (micro_op.type) {
        case Type::Add:
            micro_op.handler = BinaryArithmetic<Type::Add>;
            break;

        case Type::Mul:
            micro_op.handler = BinaryArithmetic<Type::Mul>;
            break;

        case Type::Max:
            micro_op.handler = BinaryArithmetic<Type::Max>;
            break;

        case Type::Min:
            micro_op.handler = BinaryArithmetic<Type::Min>;
            break;

        case Type::Dot3:
            micro_op.handler = BinaryArithmetic<Type::Dot3>;
            break;

        case Type::Dot4:
            micro_op.handler = BinaryArithmetic<Type::Dot4>;
            break;

        case Type::Mov:
            micro_op.handler = UnaryArithmetic<Type::Mov>;
            break;

        case Type::Floor:
            micro_op.handler = UnaryArithmetic<Type::Floor>;
            break;

        case Type::MovToAddressReg:
            micro_op.handler = WithNextOpChainedAfter<MovToAddressReg>;
            break;

        case Type::Rcp:
            micro_op.handler = WithNextOpChainedAfter<Rcp>;
            break;

        case Type::Rsq:
            micro_op.handler = WithNextOpChainedAfter<Rsq>;
            break;

        case Type::Mad:
            micro_op.handler = WithNextOpChainedAfter<Mad>;
            break;

        case Type::End:
            micro_op.handler = End;
            break;

        // Patch up ShaderCodeOffsets to MicroOpOffsets

        case Type::Goto:
            micro_op.arg0 = micro_code.block_offsets.at({ micro_op.arg0 }).value;
            micro_op.handler = MicroOpTypeErased<Goto>;
            break;

        case Type::Branch:
            micro_op.arg1 = micro_code.block_offsets.at({ micro_op.arg1 }).value;
            micro_op.arg2 = micro_code.block_offsets.at({ micro_op.arg2 }).value;
            micro_op.handler = MicroOpTypeErased<Branch>;
            break;

        case Type::Call:
        case Type::EnterLoop:
        {
            auto new_target = micro_code.block_offsets.at(ShaderCodeOffset { micro_op.arg0 });
//            auto pica_target = ShaderCodeOffset { micro_op.arg0 }.IncrementedBy(micro_op.arg1 - 1);

//            auto next_block_it = block_offsets.upper_bound(pica_target);
//            auto block_it = std::prev(next_block_it);
//            auto next_block_pos = (next_block_it == block_offsets.end()) ? MicroOpOffset { static_cast<uint32_t>(ops.size()) } : next_block_it->second;
//            if (next_block_pos < block_it->second ||
//                    !(pica_target < block_it->first.IncrementedBy(micro_op.arg1))/*
//                    || !(pica_target < next_block_it->first)*/) {
//                throw std::runtime_error("Could not find block");
//            }

//            auto new_exit_site = next_block_pos.GetPrevious();
//            ValidateContract(ops[new_exit_site.value].handler == &MicroOps::PopCallStack);
//            micro_op.arg1 = new_exit_site - new_target; // Number of instructions to execute
            micro_op.arg0 = new_target.value;
            micro_op.arg2 = micro_code.block_offsets.at(ShaderCodeOffset { micro_op.arg2 }).value;
            if (micro_op.arg0 == micro_op_offset.value) {
                throw std::runtime_error("Detected infinite loop");
            }

            if (micro_op.type == Type::EnterLoop) {
                micro_op.handler = MicroOpTypeErased<Call<true>>;
            } else {
                micro_op.handler = MicroOpTypeErased<Call<false>>;
            }
            break;
        }

        case Type::PopCallStack:
            micro_op.handler = PopCallStack;
            break;

        case Type::PrepareLoop:
            micro_op.handler = WithNextOpChainedAfter<PrepareLoop>;
            break;

        case Type::PredicateNext:
            micro_op.handler = WithNextOpChainedAfter<PredicateNext>;
            break;

        case Type::CompareEq:
            micro_op.handler = WithNextOpChainedAfter<Cmp<std::equal_to>>;
            break;

        case Type::CompareNeq:
            micro_op.handler = WithNextOpChainedAfter<Cmp<std::not_equal_to>>;
            break;

        case Type::CompareLess:
            micro_op.handler = WithNextOpChainedAfter<Cmp<std::less>>;
            break;

        case Type::CompareLeq:
            micro_op.handler = WithNextOpChainedAfter<Cmp<std::less_equal>>;
            break;

        case Type::CompareGt:
            micro_op.handler = WithNextOpChainedAfter<Cmp<std::greater>>;
            break;

        case Type::CompareGeq:
            micro_op.handler = WithNextOpChainedAfter<Cmp<std::greater_equal>>;
            break;

        case Type::EvalConditionOr:
            micro_op.handler = WithNextOpChainedAfter<EvalCondition<EvalOp::Or>>;
            break;

        case Type::EvalConditionAnd:
            micro_op.handler = WithNextOpChainedAfter<EvalCondition<EvalOp::And>>;
            break;

        case Type::EvalConditionJustX:
            micro_op.handler = WithNextOpChainedAfter<EvalCondition<EvalOp::JustX>>;
            break;

        case Type::EvalConditionJustY:
            micro_op.handler = WithNextOpChainedAfter<EvalCondition<EvalOp::JustY>>;
            break;

        case Type::Trace:
            micro_op.handler = WithNextOpChainedAfter<MicroOpTypeErased<Trace>>;
            break;

        default:
            throw std::runtime_error("Unhandled micro op type");
        }
    }
}

void MicroCodeRecompilerEngine::Reset(const Regs::VSInputRegisterMap& register_map, InputVertex& input, uint32_t num_attributes) {

    // TODO: If relative addressing is not available for input registers, can't we statically resolve references to remapped input registers?
    num_input_attributes = num_attributes;
    ranges::fill(input_register_table, &dummy_register);
    for (auto attrib_index : ranges::views::indices(num_attributes)) {
        // NOTE: Games commonly access input registers without initializing
        //       them. Generally they branch on uniform values such that the
        //       shader output does not depend on these uninitialized inputs,
        //       so this is not directly a problem. Unfortunately, we cannot
        //       statically verify games are "well-behaved" like this either,
        //       however.
        //       This has e.g. been observed in the first frame rendered in
        //       Nano Assault EX, which reads input register 2 without
        //       initializing it
        auto register_index = static_cast<uint32_t>(register_map.GetRegisterForAttribute(attrib_index));
        input_register_table[register_index] = &input.attr[attrib_index];
    }

    ranges::fill(context.conditional_code, false);
    ranges::fill(context.address_registers, 0);
    ranges::fill(context.temporary_registers, Math::Vec4<float24> { });

    global_vertex_shader_code_todo = micro_code.glsl;
}

void MicroCodeRecompilerEngine::UpdateUniforms(const std::array<Math::Vec4<float24>, 96>& uniforms) {
    ranges::copy(uniforms, context.float_uniforms.begin());
}

OutputVertex MicroCodeRecompilerEngine::Run(Context& pica_context, uint32_t entry_point) {
    TracyCZoneN(SetupInvocation, "Setup Invocation", true);

    context.call_stack.clear();
    context.call_stack.push_back({ MicroOpOffset { 0xffffffff }, {}, {}, {}, {} });

    namespace rv = ranges::views;
    ranges::fill(context.input_registers, Math::Vec4<float24>::AssignToAll(float24::FromFloat32(0.f)));
    ranges::copy(   input_register_table | rv::indirect,
                    context.input_registers.begin());

    context.micro_ops_start = micro_code.ops.data();
    context.next_micro_op = &micro_code.ops.at(micro_code.block_offsets.at(ShaderCodeOffset { entry_point }).value);
    auto first_micro_op = *context.next_micro_op++;
    TracyCZoneEnd(SetupInvocation);
    TracyCZoneN(ShaderRun, "Run", true);
    first_micro_op.handler(context, first_micro_op.arg0, first_micro_op.arg1, first_micro_op.arg2);
    TracyCZoneEnd(ShaderRun);

    // Setup output data
    // TODO: Move this into the generated micro code!
    TracyCZoneN(ShaderOutput, "Output", true);

    // Map output registers to (tightly packed) output attributes and
    // assign semantics
    // TODO(neobrain): Under some circumstances, up to 16 registers may be used. We need to
    // figure out what those circumstances are and enable the remaining registers then.
    const auto& registers = pica_context.registers;
    ValidateOutputConfiguration(registers);

    OutputVertex ret;
    for (unsigned output_reg = 0, output_attrib = 0; output_attrib < registers.shader_num_output_attributes; ++output_reg) {
        if (!(registers.vs_output_register_mask.mask() & (1 << output_reg))) {
            continue;
        }

        const auto& output_register_map = registers.shader_output_semantics[output_attrib++];

        u32 semantics[4] = {
            output_register_map.map_x, output_register_map.map_y,
            output_register_map.map_z, output_register_map.map_w
        };

        for (int comp = 0; comp < 4; ++comp) {
            float24* out = ((float24*)&ret) + semantics[comp];
            if (semantics[comp] != Regs::VSOutputAttributes::INVALID) {
                *out = context.output_registers[output_reg][comp];
            } else {
                // Zero output so that attributes which aren't output won't have denormals in them,
                // which would slow us down later.
                memset(out, 0, sizeof(*out));
            }
        }
    }


//    LOG_TRACE(Render_Software, "Output vertex: pos (%.2f, %.2f, %.2f, %.2f), col(%.2f, %.2f, %.2f, %.2f), tc0(%.2f, %.2f)",
//        ret.pos.x.ToFloat32(), ret.pos.y.ToFloat32(), ret.pos.z.ToFloat32(), ret.pos.w.ToFloat32(),
//        ret.color.x.ToFloat32(), ret.color.y.ToFloat32(), ret.color.z.ToFloat32(), ret.color.w.ToFloat32(),
//        ret.tc0.u().ToFloat32(), ret.tc0.v().ToFloat32());

    TracyCZoneEnd(ShaderOutput);
    return ret;
}

static std::string FunctionName(ShaderCodeOffset entry) {
    return fmt::format("func_{:#x}", 4 * entry.value);
}

// Maps PICA shader output register index to symbol name to use for that register.
// TODO: Un-global-ify
static std::map<int, std::string> reg_index_map;

static std::string WriteCondition(Instruction::FlowControlType instr) {
    auto component = [&](int i) {
        auto ref = (i == 0) ? instr.refx.Value() : instr.refy.Value();
        return fmt::format("{}cond.{}", (ref ? "" : "!"), "xy"[i]);
    };

    using Op = Instruction::FlowControlType::Op;

    switch (instr.op) {
    case Op::Or:
        return component(0) + " || " + component(1);

    case Op::And:
        return component(0) + " && " + component(1);

    case Op::JustX:
        return component(0);

    case Op::JustY:
        return component(1);
    }
}

static std::string TranslateToGLSL(Context& context, Instruction instr) {
    // TODO: Turn these into proper functions instead
    static auto select_input_register = [](SourceRegister reg, std::optional<unsigned> address_register_index) {
        if (address_register_index && reg.GetRegisterType() != RegisterType::FloatUniform) {
            throw std::runtime_error("Used relative register addressing with non-uniform register type");
        }

        switch (reg.GetRegisterType()) {
        case RegisterType::Input:
            return fmt::format("inreg_{}", reg.GetIndex());

        case RegisterType::Temporary:
            return fmt::format("temp_{}", reg.GetIndex());

        case RegisterType::FloatUniform:
            return fmt::format("uniforms.f[{}{}]", reg.GetIndex(), address_register_index ? fmt::format(" + a{}", *address_register_index) : "");

        default:
            __builtin_unreachable();
        }
    };

    auto select_output_register = [](nihstro::DestRegister reg) {
        switch (reg.GetRegisterType()) {
        case RegisterType::Output:
            return reg_index_map.at(reg.GetIndex());

        case RegisterType::Temporary:
            return fmt::format("temp_{}", reg.GetIndex());

        default:
            __builtin_unreachable();
        }
    };

    auto input_operand = [](SourceRegister reg, std::optional<unsigned> address_reg_index, bool negate, const char* swizzle) {
        std::string ret;
        if (negate) {
            ret += "(-";
        }
        ret += select_input_register(reg, address_reg_index);
        if (std::strcmp("xyzw", swizzle) != 0) {
            ret += '.';
            ret += swizzle;
        }
        if (negate) {
            ret += ')';
        }
        return ret;
    };

    switch (instr.opcode.Value().GetInfo().type) {
    case OpCode::Type::Arithmetic:
    {
        auto swizzle = SwizzlePattern { context.swizzle_data[instr.common.operand_desc_id] };

        bool is_inverted = 0 != (instr.opcode.Value().GetInfo().subtype & OpCode::Info::SrcInversed);
        if (is_inverted) {
            // TODO: We don't really support this properly: For instance, the address register
            //       offset needs to be applied to SRC2 instead, etc.
            //       For now, we just abort in this situation.
//            LOG_CRITICAL(HW_GPU, "Bad condition...");
//            exit(0);
//            throw Mikage::Exceptions::NotImplemented("Inverted Arithmetic op...");
        }

        // TODO: Add contract ensuring these indices are only used for uniform inputs
        std::optional<unsigned> src1_address_reg_index, src2_address_reg_index;
        if (instr.common.address_register_index != 0) {
            (is_inverted ? src2_address_reg_index : src1_address_reg_index)
                = instr.common.address_register_index.Value() - 1;
        }

        const bool negate_src1 = ((bool)swizzle.negate_src1 != false);
        const bool negate_src2 = ((bool)swizzle.negate_src2 != false);

        const char xyzw[] = "xyzw";

        // Swizzle masks constrained to active destination components
        char src1_swizzle[5] { };
        char src2_swizzle[5] { };
        char dest_swizzle[5] { };
        char* src1_swizzle_ptr = src1_swizzle;
        char* src2_swizzle_ptr = src2_swizzle;
        char* dest_swizzle_ptr = dest_swizzle;
        for (auto i : ranges::views::iota(0, 4)) {
            if (swizzle.DestComponentEnabled(i)) {
                *dest_swizzle_ptr++ = xyzw[i];
                *src1_swizzle_ptr++ = xyzw[Meta::to_underlying(swizzle.GetSelectorSrc1(i))];
                *src2_swizzle_ptr++ = xyzw[Meta::to_underlying(swizzle.GetSelectorSrc2(i))];
            }
        }

        // Full four-component swizzle masks
        char src1_swizzle_4[5] { };
        char src2_swizzle_4[5] { };
        src1_swizzle_ptr = src1_swizzle_4;
        src2_swizzle_ptr = src2_swizzle_4;
        for (auto i : ranges::views::iota(0, 4)) {
            *src1_swizzle_ptr++ = xyzw[Meta::to_underlying(swizzle.GetSelectorSrc1(i))];
            *src2_swizzle_ptr++ = xyzw[Meta::to_underlying(swizzle.GetSelectorSrc2(i))];
        }

        auto get_dest = [&]() {
            std::string ret;
            ret += select_output_register(instr.common.dest);
            if (swizzle.dest_mask != 0xf) {
                ret += '.';
                ret += dest_swizzle;
            }
            return ret;
        };

        auto get_src1 = [&](const char* swizzle) {
            return input_operand(instr.common.GetSrc1(is_inverted), src1_address_reg_index, negate_src1, swizzle);
        };

        auto get_src2 = [&](const char* swizzle) {
            return input_operand(instr.common.GetSrc2(is_inverted), src2_address_reg_index, negate_src2, swizzle);
        };

        auto num_dest_components = strlen(dest_swizzle);

        switch (instr.opcode.Value().EffectiveOpCode()) {
        case OpCode::Id::ADD:
            return get_dest() + " = " + get_src1(src1_swizzle) + " + " + get_src2(src2_swizzle) + ';';

        case OpCode::Id::DP3:
            return get_dest() + " = (non_ieee_mul(" + get_src1(src1_swizzle_4) + ".x, " + get_src2(src2_swizzle_4) + ".x) + " +
                                "non_ieee_mul(" + get_src1(src1_swizzle_4) + ".y, " + get_src2(src2_swizzle_4) + ".y) + " +
                                "non_ieee_mul(" + get_src1(src1_swizzle_4) + ".z, " + get_src2(src2_swizzle_4) + ".z)" + fmt::format(").{};", std::string(num_dest_components, 'x'));

        case OpCode::Id::DP4:
            return get_dest() + " = (non_ieee_mul(" + get_src1(src1_swizzle_4) + ".x, " + get_src2(src2_swizzle_4) + ".x) + " +
                                "non_ieee_mul(" + get_src1(src1_swizzle_4) + ".y, " + get_src2(src2_swizzle_4) + ".y) + " +
                                "non_ieee_mul(" + get_src1(src1_swizzle_4) + ".z, " + get_src2(src2_swizzle_4) + ".z) + " +
                                "non_ieee_mul(" + get_src1(src1_swizzle_4) + ".w, " + get_src2(src2_swizzle_4) + ".w)" + fmt::format(").{};", std::string(num_dest_components, 'x'));

        case OpCode::Id::DPH:
        case OpCode::Id::DPHI:
            // Like DP4, but SRC1.w is replaced with 1.0
            return get_dest() + " = (non_ieee_mul(" + get_src1(src1_swizzle_4) + ".x, " + get_src2(src2_swizzle_4) + ".x) + " +
                                "non_ieee_mul(" + get_src1(src1_swizzle_4) + ".y, " + get_src2(src2_swizzle_4) + ".y) + " +
                                "non_ieee_mul(" + get_src1(src1_swizzle_4) + ".z, " + get_src2(src2_swizzle_4) + ".z) + " +
                                get_src2(src2_swizzle_4) + ".w" + fmt::format(").{};", std::string(num_dest_components, 'x'));

        case OpCode::Id::EX2:
            return get_dest() + " = exp2(" + get_src1(src1_swizzle) + ".x)" + fmt::format(".{};", std::string(num_dest_components, 'x')) + ';';

        case OpCode::Id::LG2:
            return get_dest() + " = log2(" + get_src1(src1_swizzle) + ".x)" + fmt::format(".{};", std::string(num_dest_components, 'x')) + ';';

        case OpCode::Id::MUL:
            return get_dest() + " = non_ieee_mul(" + get_src1(src1_swizzle) + ", " + get_src2(src2_swizzle) + ");";

        case OpCode::Id::FLR:
            return get_dest() + " = floor(" + get_src1(src1_swizzle) + ");";

        case OpCode::Id::MAX:
            return get_dest() + " = max(" + get_src1(src1_swizzle) + ", " + get_src2(src2_swizzle) + ");";

        case OpCode::Id::MIN:
            return get_dest() + " = min(" + get_src1(src1_swizzle) + ", " + get_src2(src2_swizzle) + ");";

        case OpCode::Id::RCP:
        {
            auto one = (num_dest_components == 1) ? " = 1.0 / " : fmt::format(" = vec{}(1.0) / ", num_dest_components);
            return get_dest() + one + get_src1(src1_swizzle) + ".x;";
        }

        case OpCode::Id::RSQ:
            return get_dest() + " = " + "inversesqrt(" + get_src1(std::string(num_dest_components, src1_swizzle[0]).c_str()) + ");";

        case OpCode::Id::MOVA:
        {
            // TODO: Figure out how the rounding is done on hardware
            std::string ret;
            for (auto i : { 0, 1 }) {
                if (swizzle.DestComponentEnabled(i)) {
                    ret += fmt::format("a{} = int({}.{});\n", i, get_src1(src1_swizzle_4), ((i == 0) ? "x" : "y"));
                }
            }
            return ret;
        }

        case OpCode::Id::MOV:
            return get_dest() + " = " + get_src1(src1_swizzle) + ';';

        case OpCode::Id::SGE:
        case OpCode::Id::SGEI:
            if (num_dest_components == 1) {
                return fmt::format( "{} = ({} >= {}) ? 1.0 : 0.0;",
                                    get_dest(), get_src1(src1_swizzle), get_src2(src2_swizzle));
            } else {
                return fmt::format( "{} = mix(vec{}(0.0), vec{}(1.0), greaterThanEqual({}, {}));",
                                    get_dest(), num_dest_components, num_dest_components, get_src1(src1_swizzle), get_src2(src2_swizzle));
            }

        case OpCode::Id::SLT:
        case OpCode::Id::SLTI:
            if (num_dest_components == 1) {
                return fmt::format( "{} = ({} < {}) ? 1.0 : 0.0;",
                                    get_dest(), get_src1(src1_swizzle), get_src2(src2_swizzle));
            } else {
                return fmt::format( "{} = mix(vec{}(0.0), vec{}(1.0), lessThan({}, {}));",
                                    get_dest(), num_dest_components, num_dest_components, get_src1(src1_swizzle), get_src2(src2_swizzle));
            }

        case OpCode::Id::CMP:
        {
            std::string ret;
            for (auto i : { 0, 1 }) {
                auto compare_op = instr.common.compare_op;
                auto op = (i == 0) ? compare_op.x.Value() : compare_op.y.Value();

                const char* op_str = std::invoke([op, compare_op]() {
                    switch (op) {
                    case compare_op.Equal:
                        return "==";

                    case compare_op.NotEqual:
                        return "!=";

                    case compare_op.LessThan:
                        return "<";

                    case compare_op.LessEqual:
                        return "<=";

                    case compare_op.GreaterThan:
                        return ">";

                    case compare_op.GreaterEqual:
                        return ">=";

                    default:
                        throw Mikage::Exceptions::NotImplemented("Unknown compare mode {:#x}", Meta::to_underlying(op));
                    }
                });
                auto component = (i == 0) ? "x" : "y";
                ret += fmt::format( "cond.{} = {}.{} {} {}.{};\n",
                                    component, get_src1(src1_swizzle_4), component,
                                    op_str, get_src2(src2_swizzle_4), component);
            }
            return ret;
        }

        default:
            throw Mikage::Exceptions::NotImplemented("Unknown shader opcode {:#x}", Meta::to_underlying(instr.opcode.Value().EffectiveOpCode()));
        }
    }

    case OpCode::Type::MultiplyAdd:
    {
        auto swizzle = SwizzlePattern { context.swizzle_data[instr.mad.operand_desc_id] };

        const bool is_inverted = (instr.opcode.Value().EffectiveOpCode() == OpCode::Id::MADI);

        // TODO: Add contract ensuring these indices are only used for uniform inputs
        std::optional<unsigned> src2_address_reg_index, src3_address_reg_index;
        if (instr.mad.address_register_index != 0) {
            (is_inverted ? src3_address_reg_index : src2_address_reg_index)
                = instr.mad.address_register_index.Value() - 1;
        }

        const bool negate_src1 = ((bool)swizzle.negate_src1 != false);
        const bool negate_src2 = ((bool)swizzle.negate_src2 != false);
        const bool negate_src3 = ((bool)swizzle.negate_src3 != false);

        const char xyzw[] = "xyzw";
        char src1_swizzle[5] { };
        char src2_swizzle[5] { };
        char src3_swizzle[5] { };
        char dest_swizzle[5] { };
        char* src1_swizzle_ptr = src1_swizzle;
        char* src2_swizzle_ptr = src2_swizzle;
        char* src3_swizzle_ptr = src3_swizzle;
        char* dest_swizzle_ptr = dest_swizzle;
        for (auto i : ranges::views::iota(0, 4)) {
            if (swizzle.DestComponentEnabled(i)) {
                *dest_swizzle_ptr++ = xyzw[i];
                *src1_swizzle_ptr++ = xyzw[Meta::to_underlying(swizzle.GetSelectorSrc1(i))];
                *src2_swizzle_ptr++ = xyzw[Meta::to_underlying(swizzle.GetSelectorSrc2(i))];
                *src3_swizzle_ptr++ = xyzw[Meta::to_underlying(swizzle.GetSelectorSrc3(i))];
            }
        }

        auto get_dest = [&]() {
            std::string ret;
            ret += select_output_register(instr.mad.dest);
            if (swizzle.dest_mask != 0xf) {
                ret += '.';
                ret += dest_swizzle;
            }
            return ret;
        };

        auto get_src1 = [&](const char* swizzle) {
            return input_operand(instr.mad.GetSrc1(is_inverted), std::nullopt, negate_src1, swizzle);
        };

        auto get_src2 = [&](const char* swizzle) {
            return input_operand(instr.mad.GetSrc2(is_inverted), src2_address_reg_index, negate_src2, swizzle);
        };

        auto get_src3 = [&](const char* swizzle) {
            return input_operand(instr.mad.GetSrc3(is_inverted), src3_address_reg_index, negate_src3, swizzle);
        };

        return get_dest() + " = non_ieee_mul(" + get_src1(src1_swizzle) + ", " + get_src2(src2_swizzle) + ") + " + get_src3(src3_swizzle) + ';';
    }

    default:
        switch (instr.opcode.Value().EffectiveOpCode()) {
        case OpCode::Id::NOP:
            return "";

        case OpCode::Id::END:
        {
            std::string glsl = "// END\n";
            for (unsigned output_reg = 0, output_attrib = 0; true; ++output_reg) {
                if (!(context.registers.vs_output_register_mask.mask() & (1 << output_reg))) {
                    continue;
                }

                const auto& output_register_map = context.registers.shader_output_semantics[output_attrib++];

                // TODO: For now, we just always declare outputs such that they include the mapping directly. Instead, we should reassign output registers (or at least all writes to them) to consider this
                // Either way, we want a static output mapping so that we don't need to make the fragment shader inputs depend on vertex shader configuration
                u32 semantics[4] = {
                    output_register_map.map_x, output_register_map.map_y,
                    output_register_map.map_z, output_register_map.map_w
                };

                if (semantics[0] == Regs::VSOutputAttributes::POSITION_X) {
                    // gl_Position is implicitly defined
                    glsl += fmt::format("gl_Position = vec4({}.xy, -{}.z, {}.w);\n",
                                        reg_index_map.at(output_reg), reg_index_map.at(output_reg), reg_index_map.at(output_reg));
                    break;
                }
            }
            // TODO: Also must cause callers to stop executing any code after this one!
            return glsl;
        }

        case OpCode::Id::BREAKC:
            return "// TODO: Breakc";

        case OpCode::Id::CALL:
        case OpCode::Id::CALLC:
        case OpCode::Id::CALLU:
        {
            std::string prefix;
            if (instr.opcode.Value() == OpCode::Id::CALLC) {
                prefix = fmt::format("if ({}) ", WriteCondition(instr.flow_control));
            }
            if (instr.opcode.Value() != OpCode::Id::CALLU || context.shader_uniforms.b[instr.flow_control.bool_uniform_id]) {
                return prefix + FunctionName(ShaderCodeOffset { instr.flow_control.dest_offset }) + "();";
            } else {
                return "// Conditional call (statically omitted)";
            }
        }

        case OpCode::Id::IFU:
        case OpCode::Id::IFC:
            // Already encoded in CFG; nothing to do
            return "// Conditional";

        case OpCode::Id::JMPC:
        case OpCode::Id::JMPU:
            // Already encoded in CFG; nothing to do
            return "// Jump";

        case OpCode::Id::LOOP:
            // Already encoded in CFG; nothing to do
            return "// Loop";

        default:
            return "// Unknown";
        }
    }
}

void WriteBlocksFromTo(Context& context, std::string& glsl, const AnalyzedProgram& program, const ShaderCodeOffset block_offset, const ShaderCodeOffset end) {
    auto& block = program.blocks.at(block_offset);

    // TODO: Merge with function above that also defines this lambda
    auto is_same_block = [&program](ShaderCodeOffset block_start, ShaderCodeOffset b) {
        auto block_end = block_start.IncrementedBy(program.blocks.at(block_start).length);
        return !(b < block_start) && (b < block_end);
    };
    auto instr_bound = block_offset.IncrementedBy(block.length);
    if (is_same_block(block_offset, end) && end.GetNext() < instr_bound) {
        instr_bound = end;
    }
    if (block_offset != instr_bound) {
        glsl += fmt::format("// block: {:#x}..{:#x}\n", 4 * block_offset.value, 4 * instr_bound.GetPrevious().value + 3);
    }

    for (auto instr_offset : ranges::views::iota(block_offset, instr_bound)) {
        if (instr_offset == end.GetNext()) {
            return;
        }
        glsl += TranslateToGLSL(context, instr_offset.ReadFrom(context.shader_memory));
        glsl += '\n';
    }

    if (is_same_block(block_offset, end)) {
        return;
    }

    if (block.successors.size() == 0) {
        return;
    } else if (block.successors.size() == 1) {
        auto successor_offset = block.successors.begin()->first;
        WriteBlocksFromTo(context, glsl, program, successor_offset, end);
    } else {
        using SuccessionVia = AnalyzedProgram::SuccessionVia;
        ValidateContract(block.successors.size() == 2);
        std::pair<ShaderCodeOffset, SuccessionVia> branch_offsets[] =
            { *block.successors.begin(), *std::next(block.successors.begin()) };

        fmt::print(stderr, "branch offsets: {:#x} {:#x}, {} {}\n", branch_offsets[0].first.value*4, branch_offsets[1].first.value*4, Meta::to_underlying(branch_offsets[0].second), Meta::to_underlying(branch_offsets[1].second));

        // Move the "more interesting" block to index 0; the other one is expected to be a simple jump
        if (branch_offsets[1].second == SuccessionVia::BranchToIf) {
            std::swap(branch_offsets[0], branch_offsets[1]);
        }
        if (branch_offsets[1].second == SuccessionVia::ExitLoop) {
            std::swap(branch_offsets[0], branch_offsets[1]);
        }
        if (branch_offsets[1].second == SuccessionVia::CondJumpTo) {
            std::swap(branch_offsets[0], branch_offsets[1]);
        }
        if (branch_offsets[1].second == SuccessionVia::LoopEnd) {
            std::swap(branch_offsets[0], branch_offsets[1]);
        }

        auto branch_offset = block_offset.IncrementedBy(block.length - 1);
        auto branch_instr = branch_offset.ReadFrom(context.shader_memory).flow_control;

        if (branch_offsets[0].second == SuccessionVia::BranchToIf) {
            ValidateContract(branch_offsets[1].second == SuccessionVia::BranchToElse || branch_offsets[1].second == SuccessionVia::JumpTo);
            // IFU branch is statically evaluated and hence should never show up here
            ValidateContract(branch_offset.ReadFrom(context.shader_memory).opcode.Value().EffectiveOpCode() == OpCode::Id::IFC);

            auto post_dominator = block.post_dominator;

            glsl += fmt::format("if ({}) {{\n", WriteCondition(branch_instr));
            // TODO: Shouldn't this write up to branch_offsets[1].first instead????
            WriteBlocksFromTo(context, glsl, program, branch_offsets[0].first, branch_offsets[1].second == SuccessionVia::BranchToElse ? branch_offsets[1].first.GetPrevious() : post_dominator.GetPrevious());
            // Check if we have a non-empty else-body
            if (branch_offsets[1].second == SuccessionVia::BranchToElse) {
                // No else branch should be generated for IFU
                glsl += "} else {\n";
                WriteBlocksFromTo(context, glsl, program, branch_offsets[1].first, post_dominator.GetPrevious());
            }
            glsl += "}\n";

//            if (post_dominator != end) {
                WriteBlocksFromTo(context, glsl, program, post_dominator, end);
//            } else {
//                // TODO: ??
//            }
        } else if (branch_offsets[0].second == SuccessionVia::ExitLoop) {
            ValidateContract(branch_offsets[1].second == SuccessionVia::JumpTo);

            glsl += fmt::format("a2 = int(uniforms.i[{}].y);\nfor (uint count = 0; count <= uniforms.i[{}].x; a2 += int(uniforms.i[{}].z), ++count) {{\n",
                                branch_instr.int_uniform_id.Value(), branch_instr.int_uniform_id.Value(), branch_instr.int_uniform_id.Value());

            auto return_site = ShaderCodeOffset { branch_instr.dest_offset };
            WriteBlocksFromTo(context, glsl, program, branch_offsets[1].first, return_site);
            glsl += "}\n";

            WriteBlocksFromTo(context, glsl, program, branch_offsets[0].first, end);
        } else if (branch_offsets[0].second == SuccessionVia::CondJumpTo) {
            ValidateContract(branch_offsets[1].second == SuccessionVia::Fallthrough);

            // Assert that both paths converge.
            // TODO: This need not hold in general (seems to work for the majority of titles, though)
            auto post_dominator = block.post_dominator;
            ValidateContract(post_dominator != ShaderCodeOffset { 0xffffffff });

            // Inline the target blocks
            // TODO: Could we benefit from turning these into functions?
            glsl += fmt::format("if ({}) {{\n", WriteCondition(branch_instr));
            WriteBlocksFromTo(context, glsl, program, branch_offsets[0].first, post_dominator.GetPrevious());
            glsl += "} else {\n";
            WriteBlocksFromTo(context, glsl, program, branch_offsets[1].first, post_dominator.GetPrevious());
            glsl += "}\n";

            WriteBlocksFromTo(context, glsl, program, post_dominator, end);
        } else if (branch_offsets[0].second == SuccessionVia::LoopEnd) {
            // This was the last instruction of the loop: Nothing else to do
            ValidateContract(branch_offsets[1].second == SuccessionVia::JumpTo);
            return;
        } else {
            ValidateContract(false);
        }
    }
}

static std::string GenerateGLSL(Context& context, const AnalyzedProgram& program) {
    std::string glsl = "#version 460 core\n\n";

    // TODO: Un-global-ize...
    reg_index_map.clear();

    // Declare inputs
    for (auto register_index : ranges::views::iota(uint32_t { 0 }, uint32_t { 16 })) {
        glsl += fmt::format("layout(location = {}) in vec4 inreg_{};\n", register_index, register_index);
    }
    glsl += '\n';

    // Declare outputs
    ValidateOutputConfiguration(context.registers);

    for (unsigned output_reg = 0, output_attrib = 0; output_reg < context.registers.vs_output_register_mask.mask().NumBits(); ++output_reg) {
        if (!(context.registers.vs_output_register_mask.mask() & (1 << output_reg))) {
            continue;
        }

        if (output_attrib >= context.registers.shader_num_output_attributes) {
            // These registers aren't used by later pipeline stages, but the
            // shader may still write to them
            reg_index_map[output_reg] = "unused_output_" + std::to_string(output_reg);
            glsl += fmt::format("vec4 {};\n", reg_index_map.at(output_reg));
            continue;
        }

        const auto& output_register_map = context.registers.shader_output_semantics[output_attrib++];

        // TODO: For now, we assume the components of each output register
        //       are "similar" (e.g. all position or all texture coordinate).
        //       However, emulated content could mix and match different
        //       semantics in a single register.
        //
        // Either way, we want a static output mapping so that we don't need to make the fragment shader inputs depend on vertex shader configuration
        u32 semantics[4] = {
            output_register_map.map_x, output_register_map.map_y,
            output_register_map.map_z, output_register_map.map_w
        };

        using VSOutAttr = Regs::VSOutputAttributes;
        static std::map<VSOutAttr::Semantic, std::pair<int, const char*>> semantic_map = {{
            { VSOutAttr::POSITION_X, { 4, "output_pos" } },
            { VSOutAttr::QUATERNION_X, { 4, "output_quat" } },
            { VSOutAttr::COLOR_R, { 4, "output_col" } },
            { VSOutAttr::TEXCOORD0_U, { 2, "output_tex0" } },
            { VSOutAttr::TEXCOORD1_U, { 2, "output_tex1" } },
            { VSOutAttr::TEXCOORD2_U, { 2, "output_tex2" } },
            { VSOutAttr::VIEW_X, { 3, "output_view" } },
        }};

        auto primary_semantic_it = semantic_map.find(VSOutAttr::Semantic { semantics[0] });
        if (primary_semantic_it == semantic_map.end()) {
            throw std::runtime_error(fmt::format("Unknown shader output semantic {}", semantics[0]));
        }
        auto primary_semantic = primary_semantic_it->first;

        // NOTE: We currently assume the output registers use non-shuffled
        //       components that all use the same kind of semantic.
        //       E.g. we always expect the output position to be stored in a
        //       single output register, and texture coordinates to be written
        //       to separate registers each.
        // This loop checks for this assumption
        //
        // TODO: Super Mario 3D Land breaks this assumption in many ways:
        // * it stores TEXCOORD0_W in the register's w component
        // * it stores TEXCOORD0_UV and TEXCOORD1_UV in a single register
        for (auto i : ranges::views::indices(std::size(semantics))) {
            if (semantics[i] == Regs::VSOutputAttributes::INVALID) {
                continue;
            }

            fmt::print(stderr, "Semantic for register {}.{}: {}\n", output_reg, "xyzw"[i], semantics[i]);

            auto expected_difference = i;
            if (semantics[i] - Meta::to_underlying(primary_semantic) != expected_difference && semantics[i] != VSOutAttr::TEXCOORD0_W) {
                // Commented out to make Super Mario 3D Land work
//                throw std::runtime_error(fmt::format("Output register uses multiple semantics or shuffled semantic components: {} {} {}", Meta::to_underlying(primary_semantic), semantics[i], expected_difference));
            }
        }

        reg_index_map[output_reg] = primary_semantic_it->second.second;
    }

    // TODO: Make sure the shader writes the correct number of components for these!
    glsl += fmt::format("vec4 output_pos;\n"); // Written to gl_Position at the end of the shader
    glsl += fmt::format("layout(location = 0) out vec4 output_col;\n");
    glsl += fmt::format("layout(location = 1) out vec4 output_tex0;\n");
    glsl += fmt::format("layout(location = 2) out vec4 output_tex1;\n");
    glsl += fmt::format("layout(location = 3) out vec4 output_tex2;\n");
    glsl += fmt::format("layout(location = 4) out vec4 output_quat;\n");
    glsl += fmt::format("layout(location = 5) out vec4 output_view;\n");
    glsl += '\n';

    // Declare temporaries
    // TODO: Consider only declaring those temporaries actually used
    for (auto i : ranges::views::iota(0, 16)) {
        glsl += fmt::format("vec4 temp_{};\n", i);
    }
    glsl += "\n";

    // Declare index registers for relative addressing
    for (auto i : { 0, 1, 2 }) {
        glsl += fmt::format("int a{} = 0;\n", i);
    }
    glsl += "\n";

    // Declare conditional code registers
    glsl += "bvec2 cond = bvec2(false);\n\n";

    // Declare unforms
    glsl += R"(layout(std140, binding = 0) uniform Uniforms {
vec4 f[96];
uvec4 i[4];
} uniforms;

)";

    // 3DS GPU violates IEEE requirement 0.0 * inf == NaN, and instead such operations always return 0
    // Some games rely on this: E.g. TLoZ: Ocarina of Time 3D won't render certain UI elements otherwise
    const bool handle_infzero = false;
    if (handle_infzero) {
        glsl += "float non_ieee_mul(float a, float b) { return (a != 0.0f && b != 0.0f) ? (a * b) : (isnan(a) || isnan(b)) ? (a * b) : 0.0; } \n\n";
        // TODO: Use mix() instead
        glsl += "vec2 non_ieee_mul(vec2 a, vec2 b) { return vec2(non_ieee_mul(a.x, b.x), non_ieee_mul(a.y, b.y)); } \n\n";
        glsl += "vec3 non_ieee_mul(vec3 a, vec3 b) { return vec3(non_ieee_mul(a.x, b.x), non_ieee_mul(a.y, b.y), non_ieee_mul(a.z, b.z)); } \n\n";
        glsl += "vec4 non_ieee_mul(vec4 a, vec4 b) { return vec4(non_ieee_mul(a.x, b.x), non_ieee_mul(a.y, b.y), non_ieee_mul(a.z, b.z), non_ieee_mul(a.w, b.w)); } \n\n";
    } else {
        // Fallback: convert INF to FLT32_MAX before multiplication
        auto max_float = fmt::format("{}", std::numeric_limits<float>::max());
        glsl += "float non_ieee_mul(float a, float b) { return min(a, " + max_float + ") * min(b, " + max_float + "); } \n\n";
        glsl += "vec2 non_ieee_mul(vec2 a, vec2 b) { return min(a, vec2(" + max_float + ")) * min(b, vec2(" + max_float + ")); } \n\n";
        glsl += "vec3 non_ieee_mul(vec3 a, vec3 b) { return min(a, vec3(" + max_float + ")) * min(b, vec3(" + max_float + ")); } \n\n";
        glsl += "vec4 non_ieee_mul(vec4 a, vec4 b) { return min(a, vec4(" + max_float + ")) * min(b, vec4(" + max_float + ")); } \n\n";
    }

    // Forward-declare functions
    for (auto& func : program.functions) {
        if (func.entry == program.entry_point) {
            // Skip main
            continue;
        }
        glsl += "void ";
        glsl += FunctionName(func.entry);
        glsl += "();\n";
    }
    glsl += "\n";

    for (auto& func : program.functions) {
        auto func_name =
                (func.entry == program.entry_point)
                ? "main " : FunctionName(func.entry);
        glsl += fmt::format("void {}() {{{}\n", func_name, (func.entry == program.entry_point) ? fmt::format(" // {}", 4 * func.entry.value) : "");

        WriteBlocksFromTo(context, glsl, program, func.entry, func.exit);

        glsl += "}\n\n";
    }

    return glsl;
}

std::unique_ptr<ShaderEngine> CreateMicroCodeRecompiler(Context& context) try {
    auto program = AnalyzeShader(   context.shader_memory.data(),
                                    context.shader_memory.size(),
                                    context.registers.vs_bool_uniforms.Value(),
                                    context.registers.vs_main_offset);

    auto micro_code = RecompileToMicroCodeInternal( *program.program,
                                                    context.shader_memory,
                                                    context.swizzle_data,
                                                    context.registers.vs_bool_uniforms.Value(),
                                                    context.registers.vs_int_uniforms);

//    auto cfg = VisualizeShaderControlFlowGraph( *program.program,
//                                                context.shader_memory.data(),
//                                                context.shader_memory.size(),
//                                                context.swizzle_data.data(),
//                                                context.swizzle_data.size());
//    std::cerr << "GENERATE CFG:\n";
//    std::cerr << cfg << "\n";

    micro_code.glsl = GenerateGLSL(context, *program.program);
//    std::cerr << "GENERATE GLSL:\n";
//    std::cerr << micro_code.glsl << "\n";
//    std::exit(1);

    return std::make_unique<MicroCodeRecompilerEngine>(std::move(micro_code));
} catch (AnalyzedProgram& prog) {
    auto vis = VisualizeShaderControlFlowGraph(prog, context.shader_memory.data(), context.shader_memory.size(),
                                context.swizzle_data.data(), context.swizzle_data.size());
//    std::cerr << vis << "\n";
    throw std::runtime_error(fmt::format("OMG: {:#x}", context.registers.vs_main_offset.Value()));
}

} // namespace Pica::VertexShader

//++* Extract shader analysis to 2.5 branch
//++* Keep microcode runtime patches in external branch for the future
//++* Integrate video_core
//++* Integrate Android frontend
//++* DONE: Fix Android building
//++* DONE: USE_PROFILER => TRACY_ENABLE
//++* DONE: USE_DEBUG_SERVER => PISTACHE_ENABLE
//++  * Add dummy debug server
//++* DONE: Debug exts as option
//++
//++
//++Remove USE_SHADER_UBO define in renderer.cpp
//++
//++4_shader_recompiler reference: 70facbb31834e952871e95d323d93ea6ff82f41e
//++3_shader_bytecode_proto reference: 66ccc5c2b0bd8bafad20aa162f509a93d0204e06
//++  7/mar: b6b2f6be724c0169b57826eb111103a404fd2489
//++
//++XXH64_update(hash_state.get(), context.swizzle_data.data(), sizeof(context.swizzle_data));



