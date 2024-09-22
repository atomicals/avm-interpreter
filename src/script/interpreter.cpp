// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Copyright (c) 2024 The Atomicals Developers and Supporters
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>

#include <crypto/eaglesong.h>
#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <crypto/sha512.h>
#include <crypto/sha512_256.h>
#include <crypto/sha3.h>
#include <iostream>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/bitfield.h>
#include <script/script.h>
#include <script/script_flags.h>
#include <script/sigencoding.h>
#include <uint256.h>
#include <util/bitmanip.h>
#include <util/strencodings.h>
#include <script/script_num.h>

#include "json.hpp"
using json = nlohmann::json;

inline uint8_t make_rshift_mask(size_t n) {
    static uint8_t mask[] = {0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80};
    return mask[n];
}

inline uint8_t make_lshift_mask(size_t n) {
    static uint8_t mask[] = {0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01};
    return mask[n];
}

// shift x right by n bits, implements OP_RSHIFT
static valtype RShift(const valtype &x, int n) {
    int bit_shift = n % 8;
    int byte_shift = n / 8;

    uint8_t mask = make_rshift_mask(bit_shift);
    uint8_t overflow_mask = ~mask;

    valtype result(x.size(), 0x00);
    for (int i = 0; i < (int)x.size(); i++) {
        int k = i + byte_shift;
        if (k < (int)x.size()) {
            uint8_t val = (x[i] & mask);
            val >>= bit_shift;
            result[k] |= val;
        }

        if (k + 1 < (int)x.size()) {
            uint8_t carryval = (x[i] & overflow_mask);
            carryval <<= 8 - bit_shift;
            result[k + 1] |= carryval;
        }
    }
    return result;
}

// shift x left by n bits, implements OP_LSHIFT
static valtype LShift(const valtype &x, int n) {
    int bit_shift = n % 8;
    int byte_shift = n / 8;

    uint8_t mask = make_lshift_mask(bit_shift);
    uint8_t overflow_mask = ~mask;

    valtype result(x.size(), 0x00);
    for (int i = x.size() - 1; i >= 0; i--) {
        int k = i - byte_shift;
        if (k >= 0) {
            uint8_t val = (x[i] & mask);
            val <<= bit_shift;
            result[k] |= val;
        }

        if (k - 1 >= 0) {
            uint8_t carryval = (x[i] & overflow_mask);
            carryval >>= 8 - bit_shift;
            result[k - 1] |= carryval;
        }
    }
    return result;
}

bool CastToBool(const valtype &vch) {
    for (size_t i = 0; i < vch.size(); i++) {
        if (vch[i] != 0) {
            // Can be negative zero
            if (i == vch.size() - 1 && vch[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i) (stack.at(stack.size() + (i)))
#define altstacktop(i) (altstack.at(altstack.size() + (i)))
static inline void popstack(std::vector<valtype> &stack) {
    if (stack.empty()) {
        throw std::runtime_error("popstack(): stack empty");
    }
    stack.pop_back();
}

int FindAndDelete(CScript &script, const CScript &b) {
    int nFound = 0;
    if (b.empty()) {
        return nFound;
    }

    CScript result;
    CScript::const_iterator pc = script.begin(), pc2 = script.begin(), end = script.end();
    opcodetype opcode;
    do {
        result.insert(result.end(), pc2, pc);
        while (static_cast<size_t>(end - pc) >= b.size() && std::equal(b.begin(), b.end(), pc)) {
            pc = pc + b.size();
            ++nFound;
        }
        pc2 = pc;
    } while (script.GetOp(pc, opcode));

    if (nFound > 0) {
        result.insert(result.end(), pc2, end);
        script = std::move(result);
    }

    return nFound;
}

static bool IsOpcodeDisabled(opcodetype opcode, uint32_t flags) {
    switch (opcode) {
        case OP_2MUL:
        case OP_2DIV:
            // Disabled opcodes.
            return true;
        case OP_INVERT:
        case OP_MUL:
        default:
            break;
    }
    return false;
}

/**
 * A data type to abstract out the condition stack during script execution.
 *
 * Conceptually it acts like a vector of booleans, one for each level of nested
 * IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
 * each.
 *
 * The elements on the stack cannot be observed individually; we only need to
 * expose whether the stack is empty and whether or not any false values are
 * present at all. To implement OP_ELSE, a toggle_top modifier is added, which
 * flips the last value without returning it.
 *
 * This uses an optimized implementation that does not materialize the
 * actual stack. Instead, it just stores the size of the would-be stack,
 * and the position of the first false value in it.
 */
class ConditionStack {
private:
    //! A constant for m_first_false_pos to indicate there are no falses.
    static constexpr uint32_t NO_FALSE = std::numeric_limits<uint32_t>::max();

    //! The size of the implied stack.
    uint32_t m_stack_size = 0;
    //! The position of the first false value on the implied stack, or NO_FALSE
    //! if all true.
    uint32_t m_first_false_pos = NO_FALSE;

public:
    [[nodiscard]] constexpr bool empty() const noexcept { return m_stack_size == 0; }
    [[nodiscard]] constexpr bool all_true() const noexcept { return m_first_false_pos == NO_FALSE; }
    constexpr void push_back(bool f) noexcept {
        if (m_first_false_pos == NO_FALSE && !f) {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            m_first_false_pos = m_stack_size;
        }
        ++m_stack_size;
    }
    constexpr void pop_back() noexcept {
        --m_stack_size;
        if (m_first_false_pos == m_stack_size) {
            // When popping off the first false value, everything becomes true.
            m_first_false_pos = NO_FALSE;
        }
    }
    constexpr void toggle_top() noexcept {
        if (m_first_false_pos == NO_FALSE) {
            // The current stack is all true values; the first false will be the
            // top.
            m_first_false_pos = m_stack_size - 1;
        } else if (m_first_false_pos == m_stack_size - 1) {
            // The top is the first false value; toggling it will make
            // everything true.
            m_first_false_pos = NO_FALSE;
        } else {
            // There is a false value, but not on top. No action is needed as
            // toggling anything but the first false value is unobservable.
        }
    }
};

bool EvalScript(std::vector<valtype> &stack, const CScript &script, uint32_t flags, const BaseSignatureChecker &checker,
                ScriptExecutionMetrics &metrics, ScriptExecutionContextOpt const &context, ScriptError *serror,
                unsigned int *serror_op_num) {
    json a({});
    json b({});
    json c({});
    json d({});
    json e({});
    json f({});
    ScriptStateContext state(a, b, c, d, e, f);
    return EvalScript(stack, script, flags, checker, metrics, context, state, serror, serror_op_num);
}

bool EvalScript(std::vector<valtype> &stack, const CScript &script, uint32_t flags, const BaseSignatureChecker &checker,
                ScriptExecutionMetrics &metrics, ScriptExecutionContextOpt const &context,
                ScriptStateContext &stateContext, ScriptError *serror, unsigned int *serror_op_num) {
    // static auto const bnZero = CScriptNum::fromIntUnchecked(0);
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const valtype vchFalse(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    opcodetype opcode;
    valtype vchPushValue;
    ConditionStack vfExec;
    std::vector<valtype> altstack;
    set_error(serror, ScriptError::UNKNOWN);
    set_error_op_num(serror_op_num, 0);
    if (script.size() > MAX_SCRIPT_SIZE) {
        return set_error(serror, ScriptError::SCRIPT_SIZE);
    }
    int nOpCount = 0;

    size_t const maxIntegerSize = CScriptNum::MAXIMUM_ITEM_SIZE;
    ScriptError const invalidNumberRangeError = ScriptError::INVALID_NUMBER_RANGE;

    size_t const maxStateKeySize = 1024;
    try {
        unsigned int opCounter = 0;
        while (pc < pend) {
            // Set the op num up front
            set_error_op_num(serror_op_num, opCounter++);

            bool fExec = vfExec.all_true();
            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue)) {
                return set_error(serror, ScriptError::BAD_OPCODE);
            }
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE) {
                return set_error(serror, ScriptError::PUSH_SIZE);
            }

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT) {
                return set_error(serror, ScriptError::OP_COUNT);
            }

            // Some opcodes are disabled.
            if (IsOpcodeDisabled(opcode, flags)) {
                return set_error(serror, ScriptError::DISABLED_OPCODE);
            }

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (!CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, ScriptError::MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)) {
                switch (opcode) {
                    //
                    // Push value
                    //
                    case OP_1NEGATE:
                    case OP_1:
                    case OP_2:
                    case OP_3:
                    case OP_4:
                    case OP_5:
                    case OP_6:
                    case OP_7:
                    case OP_8:
                    case OP_9:
                    case OP_10:
                    case OP_11:
                    case OP_12:
                    case OP_13:
                    case OP_14:
                    case OP_15:
                    case OP_16: {
                        // ( -- value)
                        CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                        stack.push_back(bn.getvch());
                        // The result of these opcodes should always be the
                        // minimal way to push the data they push, so no need
                        // for a CheckMinimalPush here.
                    } break;

                    //
                    // Control
                    //
                    case OP_NOP:
                        break;

                    case OP_CHECKLOCKTIMEVERIFY: {
                        if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                            break;
                        }

                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        // Note that  elsewhere numeric opcodes are limited to
                        // operands in the range -2**31+1 to 2**31-1, however it
                        // is legal for opcodes to produce results exceeding
                        // that range. This limitation is implemented by
                        // CScriptNum's default 4-byte limit.
                        //
                        // If we kept to that limit we'd have a year 2038
                        // problem, even though the nLockTime field in
                        // transactions themselves is uint32 which only becomes
                        // meaningless after the year 2106.
                        //
                        // Thus as a special case we tell CScriptNum to accept
                        // up to 5-byte bignums, which are good until 2**39-1,
                        // well beyond the 2**32-1 limit of the nLockTime field
                        // itself.
                        const CScriptNum nLockTime(stacktop(-1), 5);

                        // In the rare event that the argument may be < 0 due to
                        // some arithmetic being done first, you can always use
                        // 0 MAX CHECKLOCKTIMEVERIFY.
                        if (nLockTime < 0) {
                            return set_error(serror, ScriptError::NEGATIVE_LOCKTIME);
                        }

                        // Actually compare the specified lock time with the
                        // transaction.
                        if (!checker.CheckLockTime(nLockTime)) {
                            return set_error(serror, ScriptError::UNSATISFIED_LOCKTIME);
                        }

                        break;
                    }

                    case OP_CHECKSEQUENCEVERIFY: {
                        if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                            break;
                        }

                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        // nSequence, like nLockTime, is a 32-bit unsigned
                        // integer field. See the comment in CHECKLOCKTIMEVERIFY
                        // regarding 5-byte numeric operands.
                        const CScriptNum nSequence(stacktop(-1), 5);

                        // In the rare event that the argument may be < 0 due to
                        // some arithmetic being done first, you can always use
                        // 0 MAX CHECKSEQUENCEVERIFY.
                        if (nSequence < 0) {
                            return set_error(serror, ScriptError::NEGATIVE_LOCKTIME);
                        }

                        // To provide for future soft-fork extensibility, if the
                        // operand has the disabled lock-time flag set,
                        // CHECKSEQUENCEVERIFY behaves as a NOP.
                        if ((nSequence &
                             CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != bnZero) {
                            break;
                        }

                        // Compare the specified sequence number with the input.
                        if (!checker.CheckSequence(nSequence)) {
                            return set_error(serror, ScriptError::UNSATISFIED_LOCKTIME);
                        }
                        break;
                    }

                    case OP_NOP1:
                    case OP_NOP4:
                    case OP_NOP5:
                    case OP_NOP6:
                    case OP_NOP7:
                    case OP_NOP8:
                    case OP_NOP9:
                    case OP_NOP10: {
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, ScriptError::DISCOURAGE_UPGRADABLE_NOPS);
                        }
                    } break;

                    case OP_IF:
                    case OP_NOTIF: {
                        // <expression> if [statements] [else [statements]]
                        // endif
                        bool fValue = false;
                        if (fExec) {
                            if (stack.size() < 1) {
                                std::cout << "UNBALANCED_CONDITIONAL: size < 1" << std::endl;
                                return set_error(serror, ScriptError::UNBALANCED_CONDITIONAL);
                            }
                            valtype &vch = stacktop(-1);

                            if (vch.size() > 1) {
                                return set_error(serror, ScriptError::MINIMALIF);
                            }
                            if (vch.size() == 1 && vch[0] != 1) {
                                return set_error(serror, ScriptError::MINIMALIF);
                            }

                            fValue = CastToBool(vch);
                            if (opcode == OP_NOTIF) {
                                fValue = !fValue;
                            }
                            popstack(stack);
                        }
                        vfExec.push_back(fValue);
                    } break;

                    case OP_ELSE: {
                        if (vfExec.empty()) {
                            std::cout << "UNBALANCED_CONDITIONAL: else empty" << std::endl;
                            return set_error(serror, ScriptError::UNBALANCED_CONDITIONAL);
                        }
                        vfExec.toggle_top();
                    } break;

                    case OP_ENDIF: {
                        if (vfExec.empty()) {
                            std::cout << "UNBALANCED_CONDITIONAL:end ifvfExec is empty" << std::endl;
                            return set_error(serror, ScriptError::UNBALANCED_CONDITIONAL);
                        }
                        vfExec.pop_back();
                    } break;

                    case OP_VERIFY: {
                        // (true -- ) or
                        // (false -- false) and return
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        bool fValue = CastToBool(stacktop(-1));
                        if (fValue) {
                            popstack(stack);
                        } else {
                            return set_error(serror, ScriptError::VERIFY);
                        }
                    } break;

                    case OP_RETURN: {
                        if (stack.empty()) {
                            // Terminate the execution as successful. The remaining of the script does not affect the
                            // validity (even in presence of unbalanced IFs, invalid opcodes etc)
                            return set_success(serror);
                        } else {
                            return set_error(serror, ScriptError::OP_RETURN);
                        }
                    } break;

                    //
                    // Stack ops
                    //
                    case OP_TOALTSTACK: {
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        altstack.push_back(stacktop(-1));
                        popstack(stack);
                    } break;

                    case OP_FROMALTSTACK: {
                        if (altstack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_ALTSTACK_OPERATION);
                        }
                        stack.push_back(altstacktop(-1));
                        popstack(altstack);
                    } break;

                    case OP_2DROP: {
                        // (x1 x2 -- )
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        popstack(stack);
                        popstack(stack);
                    } break;

                    case OP_2DUP: {
                        // (x1 x2 -- x1 x2 x1 x2)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch1 = stacktop(-2);
                        valtype vch2 = stacktop(-1);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    } break;

                    case OP_3DUP: {
                        // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                        if (stack.size() < 3) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch1 = stacktop(-3);
                        valtype vch2 = stacktop(-2);
                        valtype vch3 = stacktop(-1);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                        stack.push_back(vch3);
                    } break;

                    case OP_2OVER: {
                        // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                        if (stack.size() < 4) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch1 = stacktop(-4);
                        valtype vch2 = stacktop(-3);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    } break;

                    case OP_2ROT: {
                        // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                        if (stack.size() < 6) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch1 = stacktop(-6);
                        valtype vch2 = stacktop(-5);
                        stack.erase(stack.end() - 6, stack.end() - 4);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    } break;

                    case OP_2SWAP: {
                        // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                        if (stack.size() < 4) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        swap(stacktop(-4), stacktop(-2));
                        swap(stacktop(-3), stacktop(-1));
                    } break;

                    case OP_IFDUP: {
                        // (x - 0 | x x)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch = stacktop(-1);
                        if (CastToBool(vch)) {
                            stack.push_back(vch);
                        }
                    } break;

                    case OP_DEPTH: {
                        // -- stacksize
                        const CScriptNum bn(avm::bigint{stack.size()});
                        stack.push_back(bn.getvch());
                    } break;

                    case OP_DROP: {
                        // (x -- )
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        popstack(stack);
                    } break;

                    case OP_DUP: {
                        // (x -- x x)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch = stacktop(-1);
                        stack.push_back(vch);
                    } break;

                    case OP_NIP: {
                        // (x1 x2 -- x2)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        stack.erase(stack.end() - 2);
                    } break;

                    case OP_OVER: {
                        // (x1 x2 -- x1 x2 x1)
                        if (stack.size() < 2) {
                            return set_error(

                                serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch = stacktop(-2);
                        stack.push_back(vch);
                    } break;

                    case OP_PICK:
                    case OP_ROLL: {
                        // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                        // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        auto const sn = CScriptNum(stacktop(-1), maxIntegerSize);
                        const auto n{sn.getSizeType()};
                        popstack(stack);
                        if (sn < 0 || sn >= stack.size()) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype const vch = stacktop(-n - 1);
                        if (opcode == OP_ROLL) {
                            stack.erase(stack.end() - n - 1);
                        }
                        stack.push_back(vch);
                    } break;

                    case OP_ROT: {
                        // (x1 x2 x3 -- x2 x3 x1)
                        //  x2 x1 x3  after first swap
                        //  x2 x3 x1  after second swap
                        if (stack.size() < 3) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        swap(stacktop(-3), stacktop(-2));
                        swap(stacktop(-2), stacktop(-1));
                    } break;

                    case OP_SWAP: {
                        // (x1 x2 -- x2 x1)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        swap(stacktop(-2), stacktop(-1));
                    } break;

                    case OP_TUCK: {
                        // (x1 x2 -- x2 x1 x2)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype vch = stacktop(-1);
                        stack.insert(stack.end() - 2, vch);
                    } break;

                    case OP_SIZE: {
                        // (in -- in size)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        CScriptNum bn(avm::bigint{stacktop(-1).size()});
                        //auto const bn = CScriptNum::fromIntUnchecked(stacktop(-1).size());
                        stack.push_back(bn.getvch());
                    } break;

                    //
                    // Bitwise logic
                    //
                    case OP_AND:
                    case OP_OR:
                    case OP_XOR: {
                        // (x1 x2 - out)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype &vch1 = stacktop(-2);
                        valtype &vch2 = stacktop(-1);

                        // Inputs must be the same size
                        if (vch1.size() != vch2.size()) {
                            return set_error(serror, ScriptError::INVALID_OPERAND_SIZE);
                        }

                        // To avoid allocating, we modify vch1 in place.
                        switch (opcode) {
                            case OP_AND:
                                for (size_t i = 0; i < vch1.size(); ++i) {
                                    vch1[i] &= vch2[i];
                                }
                                break;
                            case OP_OR:
                                for (size_t i = 0; i < vch1.size(); ++i) {
                                    vch1[i] |= vch2[i];
                                }
                                break;
                            case OP_XOR:
                                for (size_t i = 0; i < vch1.size(); ++i) {
                                    vch1[i] ^= vch2[i];
                                }
                                break;
                            default:
                                break;
                        }

                        // And pop vch2.
                        popstack(stack);
                    } break;

                    case OP_INVERT: {
                        // (x -- out)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype &vch1 = stacktop(-1);
                        // To avoid allocating, we modify vch1 in place
                        for (size_t i = 0; i < vch1.size(); i++) {
                            vch1[i] = ~vch1[i];
                        }
                    } break;

                    case OP_LSHIFT: {
                        // (x n -- out)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        const valtype vch1 = stacktop(-2);
                        CScriptNum n(stacktop(-1), maxIntegerSize);
                        if (n < 0) {
                            return set_error(serror, ScriptError::INVALID_NUMBER_RANGE);
                        }

                        stack.pop_back();
                        stack.pop_back();

                        auto values{vch1};
                        if(n >= values.size() * bitsPerByte)
                            fill(begin(values), end(values), 0);
                        else
                        {
                            do
                            {
                                values = LShift(values, n.getint());
                                n -= CScriptNum{avm::bigint{INT32_MAX}};
                            } while(n > 0);
                        }
                        stack.push_back(values);
                    } break;

                    case OP_RSHIFT: {
                        // (x n -- out)
                        if (stack.size() < 2) {
                            return set_error( serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        const valtype vch1 = stacktop(-2);
                        CScriptNum n(stacktop(-1), maxIntegerSize);
                        if (n < 0) {
                            return set_error(serror, ScriptError::INVALID_NUMBER_RANGE);
                        }

                        stack.pop_back();
                        stack.pop_back();
                        auto values{vch1};
                        if(n >= values.size() * bitsPerByte)
                            fill(begin(values), end(values), 0);
                        else
                        {
                            do
                            {
                                values = RShift(values, n.getint());
                                n -= CScriptNum{avm::bigint{INT32_MAX}};
                            } while(n > 0);
                        }
                        stack.push_back(values);

                    } break;

                    case OP_EQUAL:
                    case OP_EQUALVERIFY:
                        // case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                        {
                            // (x1 x2 - bool)
                            if (stack.size() < 2) {
                                valtype &vch2 = stacktop(-1);
                                return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                            }
                            valtype &vch1 = stacktop(-2);
                            valtype &vch2 = stacktop(-1);

                            std::cerr << "OP_EQUAL/OP_EQUALVERIFY: val1=" << HexStr(vch1)
                                              << ", val2=" << HexStr(vch2) << std::endl;

                            bool fEqual = (vch1 == vch2);
                            // OP_NOTEQUAL is disabled because it would be too
                            // easy to say something like n != 1 and have some
                            // wiseguy pass in 1 with extra zero bytes after it
                            // (numerically, 0x01 == 0x0001 == 0x000001)
                            // if (opcode == OP_NOTEQUAL)
                            //    fEqual = !fEqual;
                            popstack(stack);
                            popstack(stack);
                            stack.push_back(fEqual ? vchTrue : vchFalse);

 
                            if (opcode == OP_EQUALVERIFY) {
                                if (fEqual) {
                                    popstack(stack);
                                } else {
                                    std::cerr << "OP_EQUAL/OP_EQUALVERIFY: val1=" << HexStr(vch1)
                                              << ", val2=" << HexStr(vch2) << std::endl;
                                    return set_error(serror, ScriptError::EQUALVERIFY);
                                }
                            }
                        }
                        break;

                    //
                    // Numeric
                    //
                    case OP_1ADD:
                    case OP_1SUB:
                    case OP_NEGATE:
                    case OP_ABS:
                    case OP_NOT:
                    case OP_0NOTEQUAL: {
                        // (in -- out)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        CScriptNum bn(stacktop(-1), maxIntegerSize);

                        switch (opcode) {
                            case OP_1ADD: {
                                bn += CScriptNum{avm::bigint{1}};
                                break;
                            }
                            case OP_1SUB: {
                                bn -= CScriptNum{avm::bigint{1}};
                                break;
                            }
                            case OP_NEGATE:
                                bn = -bn;
                                break;
                            case OP_ABS:
                                if (bn < bnZero) {
                                    bn = -bn;
                                }
                                break;
                            case OP_NOT:
                                bn = (bn == bnZero);
                                break;
                            case OP_0NOTEQUAL:
                                bn = (bn != bnZero);
                                break;
                            default:
                                assert(!"invalid opcode");
                                break;
                        }
                        popstack(stack);
                        stack.push_back(bn.getvch());
                    } break;

                    case OP_ADD:
                    case OP_SUB:
                    case OP_MUL:
                    case OP_DIV:
                    case OP_MOD:
                    case OP_BOOLAND:
                    case OP_BOOLOR:
                    case OP_NUMEQUAL:
                    case OP_NUMEQUALVERIFY:
                    case OP_NUMNOTEQUAL:
                    case OP_LESSTHAN:
                    case OP_GREATERTHAN:
                    case OP_LESSTHANOREQUAL:
                    case OP_GREATERTHANOREQUAL:
                    case OP_MIN:
                    case OP_MAX: {
                        // (x1 x2 -- out)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        CScriptNum bn1(stacktop(-2), maxIntegerSize);
                        CScriptNum bn2(stacktop(-1), maxIntegerSize);
                        CScriptNum bn;

                        switch (opcode) {
                            case OP_ADD:
                                bn = bn1 + bn2;
                                break;

                            case OP_SUB:
                                bn = bn1 - bn2;
                                break;

                            case OP_MUL:
                                bn = bn1 * bn2;
                                break;

                            case OP_DIV:
                                // denominator must not be 0
                                if (bn2 == bnZero) {
                                    return set_error(serror, ScriptError::DIV_BY_ZERO);
                                }
                                bn = bn1 / bn2;
                                break;

                            case OP_MOD:
                                // divisor must not be 0
                                if (bn2 == bnZero) {
                                    return set_error(serror, ScriptError::MOD_BY_ZERO);
                                }
                                bn = bn1 % bn2;
                                break;

                            case OP_BOOLAND:
                                bn = (bn1 != bnZero && bn2 != bnZero);
                                break;
                            case OP_BOOLOR:
                                bn = (bn1 != bnZero || bn2 != bnZero);
                                break;
                            case OP_NUMEQUAL:
                                bn = (bn1 == bn2);
                                break;
                            case OP_NUMEQUALVERIFY:
                                bn = (bn1 == bn2);
                                break;
                            case OP_NUMNOTEQUAL:
                                bn = (bn1 != bn2);
                                break;
                            case OP_LESSTHAN:
                                bn = (bn1 < bn2);
                                break;
                            case OP_GREATERTHAN:
                                bn = (bn1 > bn2);
                                break;
                            case OP_LESSTHANOREQUAL:
                                bn = (bn1 <= bn2);
                                break;
                            case OP_GREATERTHANOREQUAL:
                                bn = (bn1 >= bn2);
                                break;
                            case OP_MIN:
                                bn = (bn1 < bn2 ? bn1 : bn2);
                                break;
                            case OP_MAX:
                                bn = (bn1 > bn2 ? bn1 : bn2);
                                break;
                            default:
                                assert(!"invalid opcode");
                                break;
                        }
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(bn.getvch());

                        if (opcode == OP_NUMEQUALVERIFY) {
                            if (CastToBool(stacktop(-1))) {
                                popstack(stack);
                            } else {
                                return set_error(serror, ScriptError::NUMEQUALVERIFY);
                            }
                        }
                    } break;

                    case OP_WITHIN: {
                        // (x min max -- out)
                        if (stack.size() < 3) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        CScriptNum bn1(stacktop(-3), maxIntegerSize);
                        CScriptNum bn2(stacktop(-2), maxIntegerSize);
                        CScriptNum bn3(stacktop(-1), maxIntegerSize);

                        bool fValue = (bn2 <= bn1 && bn1 < bn3);
                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fValue ? vchTrue : vchFalse);
                    } break;

                    //
                    // Crypto
                    //
                    case OP_RIPEMD160:
                    case OP_SHA1:
                    case OP_SHA256:
                    case OP_HASH160:
                    case OP_HASH256: {
                        // (in -- hash)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype &vch = stacktop(-1);
                        valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20
                                                                                                              : 32);
                        if (opcode == OP_RIPEMD160) {
                            CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        } else if (opcode == OP_SHA1) {
                            CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        } else if (opcode == OP_SHA256) {
                            CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        } else if (opcode == OP_HASH160) {
                            CHash160().Write(vch).Finalize(vchHash);
                        } else if (opcode == OP_HASH256) {
                            CHash256().Write(vch).Finalize(vchHash);
                        }
                        popstack(stack);
                        stack.push_back(vchHash);
                    } break;

                    case OP_CHECKDATASIG:
                    case OP_CHECKDATASIGVERIFY: {
                        // (sig message pubkey -- bool)
                        if (stack.size() < 3) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        valtype const &vchSig = stacktop(-3);
                        valtype const &vchMessage = stacktop(-2);
                        valtype const &vchPubKey = stacktop(-1);

                        if (!CheckDataSignatureEncoding(vchSig, flags, serror) ||
                            !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                            // serror is set
                            return false;
                        }

                        bool fSuccess = false;
                        if (vchSig.size()) {
                            valtype vchHash(32);
                            CSHA256().Write(vchMessage.data(), vchMessage.size()).Finalize(vchHash.data());
                            fSuccess = checker.VerifySignature(vchSig, CPubKey(vchPubKey), uint256(vchHash));
                            metrics.nSigChecks += 1;

                            if (!fSuccess) {
                                return set_error(serror, ScriptError::SIG_NULLFAIL);
                            }
                        }

                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fSuccess ? vchTrue : vchFalse);
                        if (opcode == OP_CHECKDATASIGVERIFY) {
                            if (fSuccess) {
                                popstack(stack);
                            } else {
                                return set_error(serror, ScriptError::CHECKDATASIGVERIFY);
                            }
                        }
                    } break;

                    case OP_CHECKAUTHSIG: 
                    case OP_CHECKAUTHSIGVERIFY: {
                        valtype vchSig;
                        valtype vchPubKey;
                        // If a signature and pubKey are provided then they must be in the right format and valid or we error out
                        auto hasAuthSig = context->getAuthSig(vchSig);
                        auto hasAuthPubKey = context->getAuthPubKey(vchPubKey);
                        // If either the sig or public key is provided then we error out script if anything is invalid
                        if (hasAuthSig || hasAuthPubKey) {
                            if (!hasAuthSig || 
                                !hasAuthPubKey || 
                                !CheckDataSignatureEncoding(vchSig, flags, serror) ||
                                !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                                    return set_error(serror, ScriptError::INVALID_AVM_CHECKAUTHSIG);
                            }
                            // The formats are correct and now validate signature
                            auto vchMessage = context->getAuthMessage();
                            bool fSuccess = false;
                            valtype vchHash(32);
                            CSHA256().Write(vchMessage.data(), vchMessage.size()).Finalize(vchHash.data());
                            fSuccess = checker.VerifySignature(vchSig, CPubKey(vchPubKey), uint256(vchHash));
                            if (!fSuccess) {
                                return set_error(serror, ScriptError::INVALID_AVM_CHECKAUTHSIGNULL);
                            }
                            // Add the validated and authorized public key to the stack
                            stack.push_back(vchPubKey);
                        } else {
                            // If neither was provided then just indicate there is no authorized user
                            // Just indicate no authorized user attempted to be provided
                            if (opcode == OP_CHECKAUTHSIGVERIFY) {
                                // IN the case of OP_CHECKAUTHSIGVERIFY we fail the script
                                return set_error(serror, ScriptError::INVALID_AVM_CHECKAUTHSIGVERIFY);
                            } else {
                                // Otherwise we put false on the stack
                                stack.push_back(vchFalse);
                            }
                        } 
                    } break;
 
                    //
                    // Byte string operations
                    //
                    case OP_CAT: {
                        // (x1 x2 -- out)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }
                        valtype &vch1 = stacktop(-2);
                        valtype &vch2 = stacktop(-1);
                        if (vch1.size() + vch2.size() > MAX_SCRIPT_ELEMENT_SIZE) {
                            return set_error(serror, ScriptError::PUSH_SIZE);
                        }
                        vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                        popstack(stack);
                    } break;

                    case OP_SPLIT: {
                        // (in position -- x1 x2)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        const valtype &data = stacktop(-2);

                        // Make sure the split point is appropriate.
                        auto const n = CScriptNum(stacktop(-1), maxIntegerSize);

                        if(n < 0 || n > data.size())
                            return set_error(serror,
                                             ScriptError::INVALID_SPLIT_RANGE);

                        const auto position{n.getSizeType()};
                        if (position < 0 || uint64_t(position) > data.size()) {
                            return set_error(serror, ScriptError::INVALID_SPLIT_RANGE);
                        }

                        // Prepare the results in their own buffer as `data` will be invalidated.
                        valtype n1(data.begin(), data.begin() + position);
                        valtype n2(data.begin() + position, data.end());

                        // Replace existing stack values by the new values.
                        stacktop(-2) = std::move(n1);
                        stacktop(-1) = std::move(n2);
                    } break;

                    case OP_REVERSEBYTES: {
                        // (in -- out)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        valtype &data = stacktop(-1);
                        std::reverse(data.begin(), data.end());
                    } break;

                    //
                    // Conversion operations
                    //
                    case OP_NUM2BIN: {
                        // (in size -- out)
                        if (stack.size() < 2) {
                            return set_error(
                                serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        const CScriptNum n(stacktop(-1), maxIntegerSize);
                        if(n < 0 || n > std::numeric_limits<int32_t>::max())
                            return set_error(serror, ScriptError::PUSH_SIZE);

                        const auto size{n.getSizeType()};
                        if(size > MAX_SCRIPT_ELEMENT_SIZE)
                        {
                            return set_error(serror, ScriptError::PUSH_SIZE);
                        }

                        stack.pop_back();
                        auto &rawnum = stacktop(-1);

                        avm::MinimallyEncode(rawnum);
                        if (rawnum.size() > size) {
                            return set_error(serror, ScriptError::IMPOSSIBLE_ENCODING);
                        }

                        // correct size already
                        if (rawnum.size() == size) {
                            break;
                        }

                        uint8_t signbit = 0x00;
                        if (rawnum.size() > 0) {
                            signbit = rawnum.back() & 0x80;
                            rawnum[rawnum.size() - 1] &= 0x7f;
                        }
                        // Right padding
                        if (size > rawnum.size())
                        {
                            rawnum.resize(size, 0x00);
                            rawnum.back() = signbit;
                        }
                    } break;

                    case OP_BIN2NUM: {
                        // (in -- out)
                        if (stack.size() < 1) {
                            return set_error(
                                serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        auto &n = stacktop(-1);
                        avm::MinimallyEncode(n);

                        // The resulting number must be a valid number.
                        if (!avm::IsMinimallyEncoded(n, maxIntegerSize))
                        {
                            return set_error(serror, ScriptError::INVALID_NUMBER_RANGE);
                        }
                    } break;

                    // Native Introspection opcodes (Nullary)
                    case OP_TXVERSION:
                    case OP_TXINPUTCOUNT:
                    case OP_TXOUTPUTCOUNT:
                    case OP_TXLOCKTIME: {
                        if (!context) {
                            return set_error(serror, ScriptError::CONTEXT_NOT_PRESENT);
                        }

                        switch (opcode) {
                            //  Operations
                            case OP_TXVERSION: {
                                CScriptNum const bn(context->tx().nVersion());
                                stack.push_back(bn.getvch());
                            } break;
                            case OP_TXINPUTCOUNT: {
                                CScriptNum const bn(context->tx().vin().size());
                                stack.push_back(bn.getvch());
                            } break;
                            case OP_TXOUTPUTCOUNT: {
                                CScriptNum const bn(context->tx().vout().size());
                                stack.push_back(bn.getvch());
                            } break;
                            case OP_TXLOCKTIME: {
                                CScriptNum const bn(context->tx().nLockTime());
                                stack.push_back(bn.getvch());
                            } break;
                            default: {
                                assert(!"invalid opcode");
                                break;
                            }
                        }
                    } break; // end of Native Introspection opcodes (Nullary)

                    // Native Introspection opcodes (Unary)
                    case OP_OUTPOINTTXHASH:
                    case OP_OUTPOINTINDEX:
                    case OP_OUTPUTVALUE:
                    case OP_OUTPUTBYTECODE:
                    case OP_INPUTBYTECODE: 
                    case OP_INPUTSEQUENCENUMBER: {
                        if (!context) {
                            return set_error(serror, ScriptError::CONTEXT_NOT_PRESENT);
                        }

                        // (in -- out)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        auto const sn = CScriptNum(stacktop(-1), maxIntegerSize);
                        auto const index = sn.getint();

                        auto is_valid_input_index = [&] {
                            if (index < 0 || uint64_t(index) >= context->tx().vin().size()) {
                                return set_error(serror, ScriptError::INVALID_TX_INPUT_INDEX);
                            }
                            return true;
                        };
                        auto is_valid_output_index = [&] {
                            if (index < 0 || uint64_t(index) >= context->tx().vout().size()) {
                                return set_error(serror, ScriptError::INVALID_TX_OUTPUT_INDEX);
                            }
                            return true;
                        };

                        popstack(stack); // consume element

                        switch (opcode) {

                            case OP_OUTPOINTTXHASH: {
                                if (index < 0 || index >= context->tx().vin().size()) {
                                    return set_error(serror, ScriptError::INVALID_TX_INPUT_INDEX);
                                }
                                auto const &input = context->tx().vin()[index];
                                auto const &txid = input.prevout.GetTxId();
                                static_assert(TxId::size() <= MAX_SCRIPT_ELEMENT_SIZE);
                                stack.emplace_back(txid.begin(), txid.end());
                            } break;

                            case OP_OUTPOINTINDEX: {
                                if (index < 0 || index >= context->tx().vin().size()) {
                                    return set_error(serror, ScriptError::INVALID_TX_INPUT_INDEX);
                                }
                                auto const &input = context->tx().vin()[index];
                                CScriptNum const bn(input.prevout.GetN());
                                stack.push_back(bn.getvch());
                            } break;

                            case OP_INPUTBYTECODE: {
                                if ( ! is_valid_input_index()) {
                                    return false; // serror set by is_invalid_input_index lambda
                                }
                                auto const& inputScript = context->scriptSig(index);
                                if (inputScript.size() > MAX_SCRIPT_ELEMENT_SIZE) {
                                    return set_error(serror, ScriptError::PUSH_SIZE);
                                }
                                std::cout << "OP_INPUTBYTECODE: " << HexStr(inputScript) << std::endl;
                                stack.emplace_back(inputScript.begin(), inputScript.end());
                            } break;

                            case OP_INPUTSEQUENCENUMBER: {
                                if ( ! is_valid_input_index()) {
                                    return false; // serror set by is_invalid_input_index lambda
                                }
                                auto const& input = context->tx().vin()[index];
                                CScriptNum const bn(input.nSequence);
                                std::cout << "OP_INPUTSEQUENCENUMBER: " << input.nSequence << std::endl;
                                stack.push_back(bn.getvch());
                            } break;

                            case OP_OUTPUTVALUE: {
                                if (index < 0 || index >= context->tx().vout().size()) {
                                    return set_error(serror, ScriptError::INVALID_TX_OUTPUT_INDEX);
                                }
                                auto const &output = context->tx().vout()[index];
                                CScriptNum const bn(output.nValue / SATOSHI);
                                stack.push_back(bn.getvch());
                            } break;

                            case OP_OUTPUTBYTECODE: {
                                if (index < 0 || index >= context->tx().vout().size()) {
                                    return set_error(serror, ScriptError::INVALID_TX_OUTPUT_INDEX);
                                }
                                auto const &outputScript = context->tx().vout()[index].scriptPubKey;
                                if (outputScript.size() > MAX_SCRIPT_ELEMENT_SIZE) {
                                    return set_error(serror, ScriptError::PUSH_SIZE);
                                }
                                stack.emplace_back(outputScript.begin(), outputScript.end());
                            } break;
                            default: {
                                assert(!"invalid opcode");
                                break;
                            }
                        }
                    } break; // end of Native Introspection opcodes (Unary)

                    // Atomicals Virtual Machine opcodes (Unary)
                    case OP_FT_COUNT:
                    case OP_NFT_COUNT: 
                    case OP_NFT_PUT: 
                    case OP_FT_BALANCE_ADD: {
                        if (!context) {
                            return set_error(serror, ScriptError::CONTEXT_NOT_PRESENT);
                        }

                        // (in -- out)
                        if (stack.size() < 1) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        valtype &n = stacktop(-1);

                        switch (opcode) {
                            case OP_FT_BALANCE_ADD: {
                                if (n.size() != 36) {
                                    return set_error(serror, ScriptError::INVALID_ATOMICAL_REF_SIZE);
                                } 
                                uint288 atomref(n);
                                if (!stateContext.contractFtBalanceAdd(atomref)) {
                                    return set_error(serror, ScriptError::INVALID_AVM_FT_BALANCE_ADD_INVALID);
                                }
                                popstack(stack); // consume element
                            } break;

                            case OP_NFT_PUT: {
                                if (n.size() != 36) {
                                    return set_error(serror, ScriptError::INVALID_ATOMICAL_REF_SIZE);
                                } 
                                uint288 atomref(n);
                                if (!stateContext.contractNftPut(atomref)) {
                                    return set_error(serror, ScriptError::INVALID_AVM_NFT_PUT_INVALID);
                                }
                                popstack(stack); // consume element
                            } break;
                            case OP_FT_COUNT: {
                                CScriptNum const sn(n, maxIntegerSize);
                                auto const ftCountType = sn.getint();
                                if (ftCountType < 0 || ftCountType > 1) {
                                    return set_error(serror, ScriptError::INVALID_AVM_FT_COUNT_TYPE);
                                }
                                if (ftCountType == 0) {
                                    auto count = stateContext.getFtCount();
                                    popstack(stack); // consume element
                                    CScriptNum const bn(count);
                                    stack.push_back(bn.getvch());
                                } else {
                                    auto count = stateContext.getFtCountIncoming();
                                    popstack(stack); // consume element
                                    CScriptNum const bn(count);
                                    stack.push_back(bn.getvch());
                                }
                            } break;
                            case OP_NFT_COUNT: {
                                CScriptNum const sn(n, maxIntegerSize);
                                auto const nftCountType = sn.getint();
                                if (nftCountType < 0 || nftCountType > 1) {
                                    return set_error(serror, ScriptError::INVALID_AVM_NFT_COUNT_TYPE);
                                }
                                if (nftCountType == 0) {
                                    auto count = stateContext.getNftCount();
                                    popstack(stack); // consume element
                                    CScriptNum const bn(count);
                                    stack.push_back(bn.getvch());
                                } else {
                                    auto count = stateContext.getNftCountIncoming();
                                    popstack(stack); // consume element
                                    CScriptNum const bn(count);
                                    stack.push_back(bn.getvch());
                                }
                            } break;
                            default: {
                                assert(!"invalid opcode");
                                break;
                            }
                        }
                    } break;
                    // Atomicals Virtual Machine opcodes (Binary)
                    case OP_KV_EXISTS:
                    case OP_KV_GET:
                    case OP_KV_DELETE:
                    case OP_NFT_WITHDRAW:
                    case OP_HASH_FN:
                    case OP_GETBLOCKINFO:
                    case OP_DECODEBLOCKINFO:
                    case OP_FT_BALANCE:
                    case OP_FT_ITEM:
                    case OP_NFT_ITEM:
                    case OP_NFT_EXISTS: {
                        if (!context) {
                            return set_error(serror, ScriptError::CONTEXT_NOT_PRESENT);
                        }

                        // (in -- out)
                        if (stack.size() < 2) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        valtype &vch1 = stacktop(-2);
                        valtype &vch2 = stacktop(-1);

                        switch (opcode) {
                          
                            case OP_GETBLOCKINFO: {
                                CScriptNum const sn1(vch1, maxIntegerSize);
                                auto const heightNumber = sn1.getint();
                                CScriptNum const sn2(vch2, maxIntegerSize);
                                auto const blockField = sn2.getint();
                                if (blockField < 0 || blockField > 8) {
                                    return set_error(serror, ScriptError::INVALID_AVM_INVALID_BLOCKINFO_ITEM);
                                }
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                if (blockField == 0) {
                                    auto version = stateContext.getCurrentBlockInfoVersion(heightNumber);
                                    CScriptNum const bn(version);
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 1) {
                                    std::vector<uint8_t> prevHash;
                                    stateContext.getCurrentBlockInfoPrevHash(heightNumber, prevHash);
                                    stack.emplace_back(prevHash.begin(), prevHash.end());
                                } else if (blockField == 2) {
                                    std::vector<uint8_t> merkleRoot;
                                    stateContext.getCurrentBlockInfoMerkleRoot(heightNumber, merkleRoot);
                                    stack.emplace_back(merkleRoot.begin(), merkleRoot.end());
                                } else if (blockField == 3) {
                                    auto time = stateContext.getCurrentBlockInfoTime(heightNumber);
                                    CScriptNum const bn(time);
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 4) {
                                    auto bits = stateContext.getCurrentBlockInfoBits(heightNumber);
                                    CScriptNum const bn(bits);
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 5) {
                                    auto nonce = stateContext.getCurrentBlockInfoNonce(heightNumber);
                                    CScriptNum const bn(nonce);
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 6) {
                                    auto diff = stateContext.getCurrentBlockInfoDifficulty(heightNumber);
                                    CScriptNum const bn(diff);
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 7) {
                                    std::vector<uint8_t> currentblockheader;
                                    stateContext.getCurrentBlockInfoHeader(heightNumber, currentblockheader);
                                    stack.emplace_back(currentblockheader.begin(), currentblockheader.end());
                                } else if (blockField == 8) {
                                    auto currentHeight = stateContext.getCurrentBlockInfoHeight(heightNumber);
                                    CScriptNum const bn(currentHeight);
                                    stack.push_back(bn.getvch());
                                } else {
                                    return set_error(serror, ScriptError::INVALID_AVM_INVALID_BLOCKINFO_ITEM);
                                }
                            } break;
                            case OP_FT_BALANCE: {
                                if (vch1.size() != 36) {
                                    return set_error(serror, ScriptError::INVALID_ATOMICAL_REF_SIZE);
                                }
                                uint288 atomref(vch1);
                                uint64_t balance = 0;
                                CScriptNum sn(vch2, maxIntegerSize);
                                auto balanceType = sn.getint();
                                if (balanceType < 0 || balanceType > 1) {
                                    return set_error(serror, ScriptError::INVALID_AVM_FT_BALANCE_TYPE);
                                }
                                if (balanceType == 0) {
                                    balance = stateContext.contractFtBalance(atomref);
                                } else {
                                    balance = stateContext.contractFtBalanceIncoming(atomref);
                                }
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                CScriptNum const bn(balance);
                                stack.push_back(bn.getvch());
                            } break;
                            case OP_NFT_EXISTS: {
                                if (vch1.size() != 36) {
                                    return set_error(serror, ScriptError::INVALID_ATOMICAL_REF_SIZE);
                                }
                                uint288 atomref(vch1);
                                auto nftExistsType = CScriptNum(vch2, maxIntegerSize).getint();
                                if (nftExistsType < 0 || nftExistsType > 1) {
                                    return set_error(serror, ScriptError::INVALID_AVM_NFT_EXISTS_TYPE);
                                }
                                bool exists = false;
                                if (nftExistsType == 0) {
                                    exists = stateContext.contractNftExists(atomref);
                                } else {
                                    exists = stateContext.contractNftExistsIncoming(atomref);
                                }
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                stack.push_back(exists ? vchTrue : vchFalse);
                            } break;
                            case OP_FT_ITEM: {
                                auto const index = CScriptNum(vch1, maxIntegerSize).getint();
                                if (index < 0) {
                                    return set_error(serror, ScriptError::INVALID_AVM_INVALID_FT_ITEM_INDEX);
                                }
                                uint288 tokenId;
                                auto ftItemType = CScriptNum(vch2, maxIntegerSize).getint();
                                if (ftItemType < 0 || ftItemType > 1) {
                                    return set_error(serror, ScriptError::INVALID_AVM_FT_ITEM_TYPE);
                                }
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                if (ftItemType == 0) {
                                    if (stateContext.getFtItem(index, tokenId)) {
                                        stack.emplace_back(tokenId.begin(), tokenId.end());
                                    } else {
                                        // error because not valid/not found
                                        return set_error(serror, ScriptError::INVALID_AVM_INVALID_FT_ITEM_INDEX);
                                    }
                                } else {
                                    if (stateContext.getFtItemIncoming(index, tokenId)) {
                                        stack.emplace_back(tokenId.begin(), tokenId.end());
                                    } else {
                                        // error because not valid/not found
                                        return set_error(serror, ScriptError::INVALID_AVM_INVALID_FT_ITEM_INDEX);
                                    }
                                }
                            } break;
                            case OP_NFT_ITEM: {
                                auto const index = CScriptNum(vch1, maxIntegerSize).getint();
                                if (index < 0) {
                                    return set_error(serror, ScriptError::INVALID_AVM_INVALID_NFT_ITEM_INDEX);
                                }
                                uint288 tokenId;

                                auto nftItemType = CScriptNum(vch2, maxIntegerSize).getint();
                                if (nftItemType < 0 || nftItemType > 1) {
                                    return set_error(serror, ScriptError::INVALID_AVM_NFT_ITEM_TYPE);
                                }
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                if (nftItemType == 0) {
                                    if (stateContext.getNftItem(index, tokenId)) {
                                        stack.emplace_back(tokenId.begin(), tokenId.end());
                                    } else {
                                        // error because not valid/not found
                                        return set_error(serror, ScriptError::INVALID_AVM_INVALID_NFT_ITEM_INDEX);
                                    }
                                } else {
                                    if (stateContext.getNftItemIncoming(index, tokenId)) {
                                        stack.emplace_back(tokenId.begin(), tokenId.end());
                                    } else {
                                        // error because not valid/not found
                                        return set_error(serror, ScriptError::INVALID_AVM_INVALID_NFT_ITEM_INDEX);
                                    }
                                }
                            } break;
                            case OP_KV_EXISTS: {
                                bool doesKeyExist = stateContext.contractStateExists(vch1, vch2);
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                if (doesKeyExist) {
                                    stack.push_back(vchTrue);
                                } else {
                                    stack.push_back(vchFalse);
                                }
                            } break;
                            case OP_KV_GET: {
                                std::vector<uint8_t> valueVec;
                                if (stateContext.contractStateGet(vch1, vch2, valueVec)) {
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.push_back(valueVec);
                                } else {
                                    // Error because the value was not set
                                    return set_error(serror, ScriptError::INVALID_AVM_STATE_KEY_NOT_FOUND);
                                }
                            } break;
                            case OP_KV_DELETE: {
                                stateContext.contractStateDelete(vch1, vch2);
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                            } break;
                            case OP_NFT_WITHDRAW: {
                                if (vch1.size() != 36) {
                                    return set_error(serror, ScriptError::INVALID_ATOMICAL_REF_SIZE);
                                }
                                auto const index = CScriptNum(vch1, maxIntegerSize).getint();
                                if (index < 0 || uint64_t(index) >= context->tx().vout().size()) {
                                    return set_error(serror, ScriptError::INVALID_AVM_WITHDRAW_NFT_OUTPUT_INDEX);
                                }
                                uint288 atomref(vch2);
                                if (!stateContext.contractWithdrawNft(atomref, index)) {
                                    return set_error(serror, ScriptError::INVALID_AVM_WITHDRAW_NFT);
                                }
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                            } break;
                            case OP_DECODEBLOCKINFO: {
                                if (vch1.size() != 80) {
                                    return set_error(serror, ScriptError::INVALID_AVM_BLOCK_HEADER_SIZE);
                                }
                                auto const blockField = CScriptNum(vch2, maxIntegerSize).getint();
                                if (blockField < 0 || uint64_t(blockField) > 6) {
                                    return set_error(serror, ScriptError::INVALID_AVM_INVALID_BLOCKINFO_ITEM);
                                }
                                if (blockField == 0) {
                                    auto version = stateContext.getBlockInfoVersion(vch1);
                                    CScriptNum const bn(version);
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 1) {
                                    std::vector<uint8_t> prevHash;
                                    stateContext.getBlockInfoPrevHash(vch1, prevHash);
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.emplace_back(prevHash.begin(), prevHash.end());
                                } else if (blockField == 2) {
                                    std::vector<uint8_t> merkleRoot;
                                    stateContext.getBlockInfoMerkleRoot(vch1, merkleRoot);
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.emplace_back(merkleRoot.begin(), merkleRoot.end());
                                } else if (blockField == 3) {
                                    auto time = stateContext.getBlockInfoTime(vch1);
                                    CScriptNum const bn(time);
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 4) {
                                    auto bits = stateContext.getBlockInfoBits(vch1);
                                    CScriptNum const bn(bits);
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 5) {
                                    auto nonce = stateContext.getBlockInfoNonce(vch1);
                                    CScriptNum const bn(nonce);
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.push_back(bn.getvch());
                                } else if (blockField == 6) {
                                    auto diff = stateContext.getBlockInfoDifficulty(vch1);
                                    CScriptNum const bn(diff);
                                    popstack(stack); // consume element
                                    popstack(stack); // consume element
                                    stack.push_back(bn.getvch());
                                }
                            } break;
                            case OP_HASH_FN: {
                                auto const hashFuncIndex = CScriptNum(vch2, maxIntegerSize).getint();
                                if (hashFuncIndex < 0 || uint64_t(hashFuncIndex) > 3) {
                                    return set_error(serror, ScriptError::INVALID_AVM_HASH_FUNC);
                                }
                                if (hashFuncIndex == 0) {
                                    valtype vchHash(32);
                                    SHA3_256().Write(vch1).Finalize(vchHash);
                                    popstack(stack);
                                    popstack(stack);
                                    stack.push_back(vchHash);
                                }
                                else if (hashFuncIndex == 1) {
                                    valtype vchHash(64);
                                    CSHA512().Write(vch1.data(), vch1.size()).Finalize(vchHash.data());
                                    popstack(stack);
                                    popstack(stack);
                                    stack.push_back(vchHash);
                                }
                                else if (hashFuncIndex == 2) {
                                    valtype vchHash(32);
                                    CSHA512_256().Write(vch1.data(), vch1.size()).Finalize(vchHash.data());
                                    popstack(stack);
                                    popstack(stack);
                                    stack.push_back(vchHash);
                                } else if (hashFuncIndex == 3) {
                                    valtype vchHash(32);
                                    EaglesongHash(vchHash.data(), vch1.data(), vch1.size());
                                    popstack(stack);
                                    popstack(stack);
                                    stack.push_back(vchHash);
                                }
                            } break;

                            default: {
                                assert(!"invalid opcode");
                                break;
                            }
                        }
                    } break;
                    // Atomicals Virtual Machine opcodes (Ternary)
                    case OP_KV_PUT:
                    case OP_FT_WITHDRAW: {
                        if (!context) {
                            return set_error(serror, ScriptError::CONTEXT_NOT_PRESENT);
                        }

                        // (in -- out)
                        if (stack.size() < 3) {
                            return set_error(serror, ScriptError::INVALID_STACK_OPERATION);
                        }

                        valtype &vch1 = stacktop(-3);
                        valtype &vch2 = stacktop(-2);
                        valtype &vch3 = stacktop(-1);
                        switch (opcode) {

                            case OP_KV_PUT: {
                                // Limit max size of state keys
                                if (vch1.size() > maxStateKeySize) {
                                    return set_error(serror, ScriptError::INVALID_AVM_STATE_KEY_SIZE);
                                }
                                if (vch2.size() > maxStateKeySize) {
                                    return set_error(serror, ScriptError::INVALID_AVM_STATE_KEY_SIZE);
                                }
                                stateContext.contractStatePut(vch1, vch2, vch3);
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                            } break;
                            case OP_FT_WITHDRAW: {
                                if (vch3.size() != 36) {
                                    return set_error(serror, ScriptError::INVALID_ATOMICAL_REF_SIZE);
                                }
                                auto const index = CScriptNum(vch2, maxIntegerSize).getint();
                                if (index < 0 || uint64_t(index) >= context->tx().vout().size()) {
                                    return set_error(serror, ScriptError::INVALID_AVM_WITHDRAW_FT_OUTPUT_INDEX);
                                }
                                auto const &output = context->tx().vout()[index];
                                auto withdrawAmount = CScriptNum(vch1, maxIntegerSize).getint();
                                if (withdrawAmount <= 0 || withdrawAmount > output.nValue.GetSatoshis()) {
                                    return set_error(serror, ScriptError::INVALID_AVM_WITHDRAW_FT_AMOUNT);
                                }
                                uint288 atomref(vch3);
                                if (!stateContext.contractWithdrawFt(atomref, index, withdrawAmount)) {
                                    return set_error(serror, ScriptError::INVALID_AVM_WITHDRAW_FT);
                                }
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                                popstack(stack); // consume element
                            } break;
                            default: {
                                assert(!"invalid opcode");
                                break;
                            }
                        }
                    } break;
                    default:
                        return set_error(serror, ScriptError::BAD_OPCODE);
                }
            }

            // Size limits
            if (stack.size() + altstack.size() > MAX_STACK_SIZE) {
                return set_error(serror, ScriptError::STACK_SIZE);
            }
        }
    } catch (const avm::BigIntException &) {
        std::cerr << "avm::BigIntException" << std::endl;
        return set_error(serror, ScriptError::SCRIPT_ERR_BIG_INT);
    } catch (const std::exception &ex) {
        std::cerr << ex.what() << std::endl;
        return set_error(serror, ScriptError::UNKNOWN);
    }

    if (!vfExec.empty()) {
        return set_error(serror, ScriptError::UNBALANCED_CONDITIONAL);
    }

    return set_success(serror);
}

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
template <class T>
class CTransactionSignatureSerializer {
private:
    //! reference to the spending transaction (the one being serialized)
    const T &txTo;
    //! output script being consumed
    const CScript &scriptCode;
    //! input index of txTo being signed
    const unsigned int nIn;
    //! container for hashtype flags
    const SigHashType sigHashType;

public:
    CTransactionSignatureSerializer(const T &txToIn, const CScript &scriptCodeIn, unsigned int nInIn,
                                    SigHashType sigHashTypeIn)
        : txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn), sigHashType(sigHashTypeIn) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template <typename S>
    void SerializeScriptCode(S &s) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        if (itBegin != scriptCode.end()) {
            s.write((char *)&itBegin[0], it - itBegin);
        }
    }

    /** Serialize an input of txTo */
    template <typename S>
    void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is
        // serialized
        if (sigHashType.hasAnyoneCanPay()) {
            nInput = nIn;
        }
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout);
        // Serialize the script
        if (nInput != nIn) {
            // Blank out other inputs' signatures
            ::Serialize(s, CScript());
        } else {
            SerializeScriptCode(s);
        }
        // Serialize the nSequence
        if (nInput != nIn && (sigHashType.getBaseType() == BaseSigHashType::SINGLE ||
                              sigHashType.getBaseType() == BaseSigHashType::NONE)) {
            // let the others update at will
            ::Serialize(s, (int)0);
        } else {
            ::Serialize(s, txTo.vin[nInput].nSequence);
        }
    }

    /** Serialize an output of txTo */
    template <typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (sigHashType.getBaseType() == BaseSigHashType::SINGLE && nOutput != nIn) {
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        } else {
            ::Serialize(s, txTo.vout[nOutput]);
        }
    }

    /** Serialize txTo */
    template <typename S>
    void Serialize(S &s) const {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion);
        // Serialize vin
        unsigned int nInputs = sigHashType.hasAnyoneCanPay() ? 1 : txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++) {
            SerializeInput(s, nInput);
        }
        // Serialize vout
        unsigned int nOutputs =
            (sigHashType.getBaseType() == BaseSigHashType::NONE)
                ? 0
                : ((sigHashType.getBaseType() == BaseSigHashType::SINGLE) ? nIn + 1 : txTo.vout.size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++) {
            SerializeOutput(s, nOutput);
        }
        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime);
    }
};

template <class T>
uint256 GetPrevoutHash(const T &txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto &txin : txTo.vin) {
        ss << txin.prevout;
    }
    return ss.GetHash();
}

template <class T>
uint256 GetSequenceHash(const T &txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto &txin : txTo.vin) {
        ss << txin.nSequence;
    }
    return ss.GetHash();
}

template <class T>
uint256 GetOutputsHash(const T &txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto &txout : txTo.vout) {
        ss << txout;
    }
    return ss.GetHash();
}

} // namespace

template <class T>
PrecomputedTransactionData::PrecomputedTransactionData(const T &txTo) {
    hashPrevouts = GetPrevoutHash(txTo);
    hashSequence = GetSequenceHash(txTo);
    hashOutputs = GetOutputsHash(txTo);
}

// explicit instantiation
template PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction &txTo);
template PrecomputedTransactionData::PrecomputedTransactionData(const CMutableTransaction &txTo);

template <class T>
uint256 SignatureHash(const CScript &scriptCode, const T &txTo, unsigned int nIn, SigHashType sigHashType,
                      const Amount amount, const PrecomputedTransactionData *cache, uint32_t flags) {
    assert(nIn < txTo.vin.size());

    uint256 hashPrevouts;
    uint256 hashSequence;
    uint256 hashOutputs;

    if (!sigHashType.hasAnyoneCanPay()) {
        hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);
    }

    if (!sigHashType.hasAnyoneCanPay() && (sigHashType.getBaseType() != BaseSigHashType::SINGLE) &&
        (sigHashType.getBaseType() != BaseSigHashType::NONE)) {
        hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
    }

    if ((sigHashType.getBaseType() != BaseSigHashType::SINGLE) &&
        (sigHashType.getBaseType() != BaseSigHashType::NONE)) {
        hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
    } else if ((sigHashType.getBaseType() == BaseSigHashType::SINGLE) && (nIn < txTo.vout.size())) {
        CHashWriter ss(SER_GETHASH, 0);
        ss << txTo.vout[nIn];
        hashOutputs = ss.GetHash();
    }

    CHashWriter ss(SER_GETHASH, 0);
    // Version
    ss << txTo.nVersion;
    // Input prevouts/nSequence (none/all, depending on flags)
    ss << hashPrevouts;
    ss << hashSequence;
    // The input being signed (replacing the scriptSig with scriptCode +
    // amount). The prevout may already be contained in hashPrevout, and the
    // nSequence may already be contain in hashSequence.
    ss << txTo.vin[nIn].prevout;
    ss << scriptCode;
    ss << amount;
    ss << txTo.vin[nIn].nSequence;
    // Outputs (none/one/all, depending on flags)
    ss << hashOutputs;
    // Locktime
    ss << txTo.nLockTime;
    // Sighash type
    ss << sigHashType;

    return ss.GetHash();
}

bool BaseSignatureChecker::VerifySignature(const std::vector<uint8_t> &vchSig, const CPubKey &pubkey,
                                           const uint256 &sighash) const {
    if (vchSig.size() == 64) {
        return pubkey.VerifySchnorr(sighash, vchSig);
    } else {
        return pubkey.VerifyECDSA(sighash, vchSig);
    }
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckSig(const std::vector<uint8_t> &vchSigIn,
                                                     const std::vector<uint8_t> &vchPubKey, const CScript &scriptCode,
                                                     uint32_t flags) const {
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid()) {
        return false;
    }

    // Hash type is one byte tacked on to the end of the signature
    std::vector<uint8_t> vchSig(vchSigIn);
    if (vchSig.empty()) {
        return false;
    }
    SigHashType sigHashType = GetHashType(vchSig);
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, sigHashType, amount, this->txdata, flags);

    if (!VerifySignature(vchSig, pubkey, sighash)) {
        return false;
    }

    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckLockTime(const CScriptNum &nLockTime) const {
    // There are two kinds of nLockTime: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nLockTime <
    // LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nLockTime being tested is the same as the nLockTime in the
    // transaction.
    if (!((txTo->nLockTime < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) ||
          (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD))) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nLockTime > int64_t(txTo->nLockTime)) {
        return false;
    }

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been finalized by setting
    // nSequence to maxint. The transaction would be allowed into the
    // blockchain, making the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to prevent this condition.
    // Alternatively we could test all inputs, but testing just this input
    // minimizes the data required to prove correct CHECKLOCKTIMEVERIFY
    // execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence) {
        return false;
    }

    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckSequence(const CScriptNum &nSequence) const {
    // Relative lock times are supported by comparing the passed in operand to
    // the sequence number of the input.
    const int64_t txToSequence = int64_t(txTo->vin[nIn].nSequence);

    // Fail if the transaction's version number is not set high enough to
    // trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo->nVersion) < 2) {
        return false;
    }

    // Sequence numbers with their most significant bit set are not consensus
    // constrained. Testing that the transaction's sequence number do not have
    // this bit set prevents using this property to get around a
    // CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
        return false;
    }

    // Mask off any bits that do not have consensus-enforced meaning before
    // doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;
    
    // There are two kinds of nSequence: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nSequenceMasked <
    // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nSequenceMasked being tested is the same as the nSequenceMasked in the
    // transaction.
    if (!((txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
          (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nSequenceMasked > txToSequenceMasked) {
        return false;
    }

    return true;
}

// explicit instantiation
template class GenericTransactionSignatureChecker<CTransaction>;
template class GenericTransactionSignatureChecker<CMutableTransaction>;

bool VerifyScriptAvm(const CScript &scriptSig, const CScript &scriptPubKey, uint32_t flags,
                     const BaseSignatureChecker &checker, ScriptExecutionMetrics &metricsOut,
                     ScriptExecutionContextOpt const &context, ScriptStateContext &stateContext, ScriptError *serror,
                     unsigned int *serror_op_num) {
    set_error(serror, ScriptError::UNKNOWN);
    set_error_op_num(serror_op_num, 0);

    // Always expect push only
    if (!scriptSig.IsPushOnly()) {
        return set_error(serror, ScriptError::SIG_PUSHONLY);
    }

    ScriptExecutionMetrics metrics = {};

    std::vector<valtype> stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, metrics, context, stateContext, serror, serror_op_num)) {
        // serror is set
        return false;
    }
    if (!EvalScript(stack, scriptPubKey, flags, checker, metrics, context, stateContext, serror, serror_op_num)) {
        // serror serror
        return set_error(serror, *serror);
    }
    if (stack.empty()) {
        return set_error(serror, ScriptError::EVAL_FALSE);
    }
    if (CastToBool(stack.back()) == false) {
        return set_error(serror, ScriptError::EVAL_FALSE);
    }

    // Expect clean stack
    if (stack.size() != 1) {
        return set_error(serror, ScriptError::CLEANSTACK);
    }
    metricsOut = metrics;
    return set_success(serror);
}
