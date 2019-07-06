#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <unistd.h>

#define BACKDOOR_ADDR       0x3721B360
#define PAGE_TABLE_MASK     0xFFFFF000
#define PAGE_MASK           0x00000FFF
#define PAGE_SIZE           0x1000

#define CACHE_DATA_MASK     0x0000001F
#define CACHELINE_MASK      0x000003E0
#define CACHE_TAG_MASK      0xFFFFFC00

#define PAGE_FAULT          (-1)
#define PRIV_ERROR          (-2)
#define INVALID_INSTRUCTION (-3)
#define DIVIDE_BY_ZERO      (-4)
#define TIME_OUT            (-101)
#define CPU_HALT            (-102)
#define UNKNOWN_ERROR       (-1111)

// load
#define INSTRUCTION_LB        10
#define INSTRUCTION_LH        11
#define INSTRUCTION_LW        12
#define INSTRUCTION_LBU       14
#define INSTRUCTION_LHU       15

// store
#define INSTRUCTION_SB        20
#define INSTRUCTION_SH        21
#define INSTRUCTION_SW        22

// shift
#define INSTRUCTION_SLL       30
#define INSTRUCTION_SLLI      33
#define INSTRUCTION_SRL       36
#define INSTRUCTION_SRLI      39
#define INSTRUCTION_SRA       42
#define INSTRUCTION_SRAI      45

// arithmetic
#define INSTRUCTION_ADD       50
#define INSTRUCTION_ADDI      53
#define INSTRUCTION_SUB       56
#define INSTRUCTION_LUI       59
#define INSTRUCTION_AUIPC     60

// logical
#define INSTRUCTION_XOR       70
#define INSTRUCTION_XORI      71
#define INSTRUCTION_OR        72
#define INSTRUCTION_ORI       73
#define INSTRUCTION_AND       74
#define INSTRUCTION_ANDI      75

// compare
#define INSTRUCTION_SLT       80
#define INSTRUCTION_SLTI      81
#define INSTRUCTION_SLTU      82
#define INSTRUCTION_SLTIU     83

// branch
#define INSTRUCTION_BEQ       90
#define INSTRUCTION_BNE       91
#define INSTRUCTION_BLT       92
#define INSTRUCTION_BGE       93
#define INSTRUCTION_BLTU      94
#define INSTRUCTION_BGEU      95

// jump and link
#define INSTRUCTION_JAL       100
#define INSTRUCTION_JALR      101

// multiply/divide
#define INSTRUCTION_MUL       110
#define INSTRUCTION_MULH      113
#define INSTRUCTION_MULHSU    114
#define INSTRUCTION_MULHU     115
#define INSTRUCTION_DIV       116
#define INSTRUCTION_DIVU      119
#define INSTRUCTION_REM       120
#define INSTRUCTION_REMU      123

// meta
#define INSTRUCTION_SUCCESS   221
#define INSTRUCTION_FAIL      222
#define INSTRUCTION_SETEH     223
#define INSTRUCTION_RDEC      224
#define INSTRUCTION_RDEPC     225
#define INSTRUCTION_RDTSC     226
#define INSTRUCTION_HALT      227
#define INSTRUCTION_BJP       228
#define INSTRUCTION_PCTX      229


typedef struct ctx {
    uint32_t regs[32];
    uint32_t pc;
    int priv;
} _ctx;

typedef struct cacheline {
    int valid;
    int priv;
    uint32_t tag;
    uint8_t data[32];
} _cacheline;

typedef struct cache {
    _cacheline CACHELINE[2];
    int LRU;
} _cache;

typedef struct instruction_format {
    char format;
    char* mnemonic;
    uint32_t opcode;
    uint32_t funct7;
    uint32_t funct3;
    int check_funct7;
    int check_funct3;
    int operation;
} _instruction_format;

typedef struct R_instruction {
    uint32_t opcode : 7, rd : 5, funct3 : 3, rs1 : 5, rs2 : 5, funct7 : 7;
} _R_instruction;

typedef struct I_instruction {
    uint32_t opcode : 7, rd : 5, funct3 : 3, rs1 : 5, imm0_11 : 12;
} _I_instruction;

typedef struct S_instruction {
    uint32_t opcode : 7, imm0_4 : 5, funct3 : 3, rs1 : 5, rs2 : 5, imm5_11 : 7;
} _S_instruction;

typedef struct B_instruction {
    uint32_t opcode : 7, imm11 : 1, imm1_4 : 4, funct3 : 3, rs1 : 5, rs2 : 5, imm5_10 : 6, imm12 : 1;
} _B_instruction;

typedef struct U_instruction {
    uint32_t opcode : 7, rd : 5, imm12_31 : 20;
} _U_instruction;

typedef struct J_instruction {
    uint32_t opcode : 7, rd : 5, imm12_19 : 8, imm11 : 1, imm1_10 : 10, imm20 : 1;
} _J_instruction;

typedef struct M_instruction {
    uint32_t opcode : 7, rd : 5, funct3 : 3, und : 10, funct7 : 7;
} _M_instruction;

typedef struct N_instruction {
    uint32_t opcode : 7, funct3 : 3, funct7 : 7, rd : 5, rs1 : 5, rs2 : 5;
} _N_instruction;

typedef union ins {
        uint32_t ins;
        _R_instruction R;
        _I_instruction I;
        _S_instruction S;
        _B_instruction B;
        _U_instruction U;
        _J_instruction J;
        _M_instruction M;
        _N_instruction N;
} _ins;

typedef struct instruction {
    char* mnemonic;
    char format;
    int operation;

    _ins instruction;

    uint32_t imm;
} _instruction;

#define NUM_INSTRUCTIONS 200
_instruction_format INSF[NUM_INSTRUCTIONS];
_ctx CTX;
_cache CACHE[32];
uint32_t TSC;
uint32_t err_handler = (uint32_t)-1;
uint32_t last_err_code;
uint32_t last_err_pc;

void* MEM;
void* BACKDOOR;

uint32_t sign_extend(uint32_t num, int bits){
    int sign = (num >> (bits - 1)) & 1;
    if(sign == 1){
        uint32_t extended = (uint32_t)-1;
        for(int i = 0; i < bits; i++){
            extended = extended & ~((uint32_t)1 << i);
        }
        num = num | extended;
    }
    return num;
}

void ctx_print(){
    for(int i = 0; i < 32; i++){
        printf("r%02d: %08x\n", i, CTX.regs[i]);
    }
    printf("pc:  %08x\n", CTX.pc);
}

void exception_raise(int err){
    printf("\n=======================\n");
    switch(err){
        case PAGE_FAULT:
            printf("PAGE FAULT\n");
            break;
        case PRIV_ERROR:
            printf("PRIVILEGE ERROR\n");
            break;
        case INVALID_INSTRUCTION:
            printf("INVALID INSTRUCTION\n");
            break;
        case DIVIDE_BY_ZERO:
            printf("DEVIDED BY ZERO\n");
            break;
        case CPU_HALT:
            printf("CPU HALTED\n");
            break;
        case TIME_OUT:
            printf("TIME OUT!\n");
            break;
        default:
            printf("UNKNOWN ERROR, please report to organizer.\n");
    }
    ctx_print();
    if(err < -100 || err_handler == (uint32_t)-1)
        exit(0);
    last_err_pc = CTX.pc;
    last_err_code = err;
    CTX.pc = err_handler;
    TSC++;
}

int cache_get_set(uint32_t addr){
    _cacheline* pcl = CACHE[(addr & CACHELINE_MASK) >> 5].CACHELINE;
    if(pcl[0].tag == (addr & CACHE_TAG_MASK)){
        if(pcl[0].valid == 1){
            return 0;
        }
    }
    if(pcl[1].tag == (addr & CACHE_TAG_MASK)){
        if(pcl[1].valid == 1){
            return 1;
        }
    }
    return -1;
}

void cache_commit(uint32_t addr, uint8_t* data){
    if((addr & PAGE_TABLE_MASK) == 0){
        memcpy((uint8_t*)MEM + (addr & PAGE_MASK), data, 32);
    } else if((addr & PAGE_TABLE_MASK) == (BACKDOOR_ADDR & PAGE_TABLE_MASK)){
        memcpy((uint8_t*)BACKDOOR + (addr & PAGE_MASK), data, 32);
    } else{
        exception_raise(UNKNOWN_ERROR);
    };
    TSC += 40;
}

void cache_fetch(uint32_t addr, void* p, int priv){
    _cache* pcc = &CACHE[(addr & CACHELINE_MASK) >> 5];
    int set = 0;
    if(pcc->CACHELINE[0].valid == 0){
        set = 0;
    } else if(pcc->CACHELINE[1].valid == 0){
        set = 1;
    } else{
        set = pcc->LRU;
    }
    if(pcc->CACHELINE[set].valid == 1){
        cache_commit(pcc->CACHELINE[set].tag | (addr & CACHELINE_MASK), pcc->CACHELINE[set].data);
    }
    pcc->CACHELINE[set].valid = 1;
    pcc->CACHELINE[set].priv = priv;
    pcc->CACHELINE[set].tag = addr & CACHE_TAG_MASK;
    memcpy(pcc->CACHELINE[set].data, (uint8_t*)p + (addr & PAGE_MASK & ~CACHE_DATA_MASK), 32);
    TSC += 40;
}

int cache_load_byte(uint32_t addr, uint8_t* byte, int set, int priv){
    _cacheline* pcl = &CACHE[(addr & CACHELINE_MASK) >> 5].CACHELINE[set];
    if(pcl->priv < priv)
        return PRIV_ERROR;
    *byte = pcl->data[addr & CACHE_DATA_MASK];
    CACHE[(addr & CACHELINE_MASK) >> 5].LRU = 1 - set;
    return 0;
}

int cache_store_byte(uint32_t addr, uint8_t byte, int set, int priv){
    _cacheline* pcl = &CACHE[(addr & CACHELINE_MASK) >> 5].CACHELINE[set];
    if(pcl->priv -1 < priv)
        return PRIV_ERROR;
    pcl->data[addr & CACHE_DATA_MASK] = byte;
    CACHE[(addr & CACHELINE_MASK) >> 5].LRU = 1 - set;
    return 0;
}

int mem_load_byte(uint32_t addr, uint8_t* byte, int priv){
    int set = cache_get_set(addr);
    if(set != -1){
        return cache_load_byte(addr, byte, set, priv);
    }
    if((addr & PAGE_TABLE_MASK) == 0){
        cache_fetch(addr, MEM, 0);
        return mem_load_byte(addr, byte, priv);
    } else if((addr & PAGE_TABLE_MASK) == (BACKDOOR_ADDR & PAGE_TABLE_MASK)){
        if(-1 < priv)
            return PRIV_ERROR;
        cache_fetch(addr, BACKDOOR, -1);
        return mem_load_byte(addr, byte, priv);
    } else{
        return PAGE_FAULT;
    }
}

int mem_store_byte(uint32_t addr, uint8_t byte, int priv){
    int set = cache_get_set(addr);
    if(set != -1){
        return cache_store_byte(addr, byte, set, priv);
    }
    if((addr & PAGE_TABLE_MASK) == 0){
        cache_fetch(addr, MEM, 0);
        return mem_store_byte(addr, byte, priv);
    } else if((addr & PAGE_TABLE_MASK) == (BACKDOOR_ADDR & PAGE_TABLE_MASK)){
        if(-1 < priv)
            return PRIV_ERROR;
        cache_fetch(addr, BACKDOOR, -1);
        return mem_store_byte(addr, byte, priv);
    } else{
        return PAGE_FAULT;
    }
}

int mem_load(uint32_t addr, uint8_t* byte, uint8_t len, int priv){
    for(uint8_t i = 0; i < len; i++){
        int err = 0;
        if((err = mem_load_byte(addr + i, byte + i, priv)) != 0)
            return err;
    }
    TSC++;
    return 0;
}

int mem_store(uint32_t addr, uint8_t* byte, uint8_t len, int priv){
    for(uint8_t i = 0; i < len; i++){
        int err = 0;
        if((err = mem_store_byte(addr + i, byte[i], priv)) != 0)
            return err;
    }
    TSC++;
    return 0;
}

void initialize_format(_instruction_format* format, char* mnemonic, int operation, char format_code, uint32_t opcode,
                       uint32_t funct3, int check_funct3, uint32_t funct7, int check_funct7){
    format->format = format_code;
    format->mnemonic = mnemonic;
    format->opcode = opcode;
    format->funct3 = funct3;
    format->funct7 = funct7;
    format->check_funct7 = check_funct7;
    format->check_funct3 = check_funct3;
    format->operation = operation;
}

void initialize_formats(){
    int i = 0;

    // load
    initialize_format(&INSF[i++], "lb", INSTRUCTION_LB, 'I', 0x03, 0, 1, 0, 0);
    initialize_format(&INSF[i++], "lh", INSTRUCTION_LH, 'I', 0x03, 1, 1, 0, 0);
    initialize_format(&INSF[i++], "lw", INSTRUCTION_LW, 'I', 0x03, 2, 1, 0, 0);
    initialize_format(&INSF[i++], "lbu", INSTRUCTION_LBU, 'I', 0x03, 4, 1, 0, 0);
    initialize_format(&INSF[i++], "lhu", INSTRUCTION_LHU, 'I', 0x03, 5, 1, 0, 0);

    // store
    initialize_format(&INSF[i++], "sb", INSTRUCTION_SB, 'S', 0x23, 0, 1, 0, 0);
    initialize_format(&INSF[i++], "sh", INSTRUCTION_SH, 'S', 0x23, 1, 1, 0, 0);
    initialize_format(&INSF[i++], "sw", INSTRUCTION_SW, 'S', 0x23, 2, 1, 0, 0);

    // shift
    initialize_format(&INSF[i++], "sll", INSTRUCTION_SLL, 'R', 0x33, 1, 1, 0, 1);
    initialize_format(&INSF[i++], "slli", INSTRUCTION_SLLI, 'I', 0x13, 1, 1, 0, 1);
    initialize_format(&INSF[i++], "srl", INSTRUCTION_SRL, 'R', 0x33, 5, 1, 0, 1);
    initialize_format(&INSF[i++], "srli", INSTRUCTION_SRLI, 'I', 0x13, 5, 1, 0, 1);
    initialize_format(&INSF[i++], "sra", INSTRUCTION_SRA, 'R', 0x33, 5, 1, 20, 1);
    initialize_format(&INSF[i++], "srai", INSTRUCTION_SRAI, 'I', 0x13, 5, 1, 20, 1);

    // arithmetic
    initialize_format(&INSF[i++], "add", INSTRUCTION_ADD, 'R', 0x33, 0, 1, 0, 1);
    initialize_format(&INSF[i++], "addi", INSTRUCTION_ADDI, 'I', 0x13, 0, 1, 0, 0);
    initialize_format(&INSF[i++], "sub", INSTRUCTION_SUB, 'R', 0x33, 0, 1, 0x20, 1);
    initialize_format(&INSF[i++], "lui", INSTRUCTION_LUI, 'U', 0x37, 0, 0, 0, 0);
    initialize_format(&INSF[i++], "auipc", INSTRUCTION_AUIPC, 'U', 0x17, 0, 0, 0, 0);

    // logical
    initialize_format(&INSF[i++], "xor", INSTRUCTION_XOR, 'R', 0x33, 4, 1, 0, 1);
    initialize_format(&INSF[i++], "xori", INSTRUCTION_XORI, 'I', 0x13, 4, 1, 0, 0);
    initialize_format(&INSF[i++], "or", INSTRUCTION_OR, 'R', 0x33, 6, 1, 0, 1);
    initialize_format(&INSF[i++], "ori", INSTRUCTION_ORI, 'I', 0x13, 6, 1, 0, 0);
    initialize_format(&INSF[i++], "and", INSTRUCTION_AND, 'R', 0x33, 7, 1, 0, 1);
    initialize_format(&INSF[i++], "andi", INSTRUCTION_ANDI, 'I', 0x13, 7, 1, 0, 0);

    // compare
    initialize_format(&INSF[i++], "slt", INSTRUCTION_SLT, 'R', 0x33, 2, 1, 0, 1);
    initialize_format(&INSF[i++], "slti", INSTRUCTION_SLTI, 'I', 0x13, 2, 1, 0, 0);
    initialize_format(&INSF[i++], "sltu", INSTRUCTION_SLTU, 'R', 0x33, 3, 1, 0, 1);
    initialize_format(&INSF[i++], "sltiu", INSTRUCTION_SLTIU, 'I', 0x13, 3, 1, 0, 0);

    // branch
    initialize_format(&INSF[i++], "beq", INSTRUCTION_BEQ, 'B', 0x63, 0, 1, 0, 0);
    initialize_format(&INSF[i++], "bne", INSTRUCTION_BNE, 'B', 0x63, 1, 1, 0, 0);
    initialize_format(&INSF[i++], "blt", INSTRUCTION_BLT, 'B', 0x63, 4, 1, 0, 0);
    initialize_format(&INSF[i++], "bge", INSTRUCTION_BGE, 'B', 0x63, 5, 1, 0, 0);
    initialize_format(&INSF[i++], "bltu", INSTRUCTION_BLTU, 'B', 0x63, 6, 1, 0, 0);
    initialize_format(&INSF[i++], "bgeu", INSTRUCTION_BGEU, 'B', 0x63, 7, 1, 0, 0);

    // jump and link
    initialize_format(&INSF[i++], "jal", INSTRUCTION_JAL, 'J', 0x6F, 0, 0, 0, 0);
    initialize_format(&INSF[i++], "jalr", INSTRUCTION_JALR, 'I', 0x67, 0, 1, 0, 0);

    // multiply/divide
    initialize_format(&INSF[i++], "mul", INSTRUCTION_MUL, 'R', 0x33, 0, 1, 1, 1);
    initialize_format(&INSF[i++], "mulh", INSTRUCTION_MULH, 'R', 0x33, 1, 1, 1, 1);
    initialize_format(&INSF[i++], "mulhsu", INSTRUCTION_MULHSU, 'R', 0x33, 2, 1, 1, 1);
    initialize_format(&INSF[i++], "mulhu", INSTRUCTION_MULHU, 'R', 0x33, 3, 1, 1, 1);
    initialize_format(&INSF[i++], "div", INSTRUCTION_DIV, 'R', 0x33, 4, 1, 1, 1);
    initialize_format(&INSF[i++], "divu", INSTRUCTION_DIVU, 'R', 0x33, 5, 1, 1, 1);
    initialize_format(&INSF[i++], "rem", INSTRUCTION_REM, 'R', 0x33, 6, 1, 1, 1);
    initialize_format(&INSF[i++], "remu", INSTRUCTION_REMU, 'R', 0x33, 7, 1, 1, 1);

    // meta
    initialize_format(&INSF[i++], "suc", INSTRUCTION_SUCCESS, 'M', 0x5a, 0, 1, 0, 1);
    initialize_format(&INSF[i++], "fail", INSTRUCTION_FAIL, 'M', 0x5a, 0, 1, 1, 1);
    initialize_format(&INSF[i++], "seteh", INSTRUCTION_SETEH, 'M', 0x5a, 0, 1, 2, 1);
    initialize_format(&INSF[i++], "rdec", INSTRUCTION_RDEC, 'M', 0x5a, 0, 1, 3, 1);
    initialize_format(&INSF[i++], "rdepc", INSTRUCTION_RDEPC, 'M', 0x5a, 0, 1, 4, 1);
    initialize_format(&INSF[i++], "rdtsc", INSTRUCTION_RDTSC, 'M', 0x5a, 0, 1, 5, 1);
    initialize_format(&INSF[i++], "bjp", INSTRUCTION_BJP, 'M', 0x60, 5, 1, 113, 1);
    initialize_format(&INSF[i++], "pctx", INSTRUCTION_PCTX, 'M', 0x5a, 0, 1, 7, 1);
    initialize_format(&INSF[i++], "halt", INSTRUCTION_HALT, 'M', 0x00, 0, 1, 0, 1);

    assert(i < NUM_INSTRUCTIONS);
}

_instruction_format* get_instruction_format_from_instruction(uint8_t* ins, uint32_t opcode, uint32_t funct3,
                                                             uint32_t funct7, uint32_t* imm){
    *imm = 0;

    _instruction_format* format = 0;
    for(int i = 0; i < NUM_INSTRUCTIONS; i++)
        if(INSF[i].opcode == opcode &&
            (!INSF[i].check_funct3 || (INSF[i].check_funct3 && INSF[i].funct3 == funct3)) &&
            (!INSF[i].check_funct7 || (INSF[i].check_funct7 && INSF[i].funct7 == funct7))){
            format = &INSF[i];
            break;
        }
    if(!format)
        return 0;

    if(format->format == 'R' || format->format == 'M'){} else if(format->format == 'I'){
        *imm = ((_I_instruction*)ins)->imm0_11;
    } else if(format->format == 'S'){
        *imm = (((_S_instruction*)ins)->imm5_11 << 5) | (((_S_instruction*)ins)->imm0_4);
    } else if(format->format == 'B'){
        *imm = (((_B_instruction*)ins)->imm1_4 << 1) | (((_B_instruction*)ins)->imm11 << 11) | (((_B_instruction*)ins)->
            imm5_10 << 5) | (((_B_instruction*)ins)->imm12 << 12);
    } else if(format->format == 'U'){
        *imm = (((_U_instruction*)ins)->imm12_31 << 12);
    } else if(format->format == 'J'){
        *imm = (((_J_instruction*)ins)->imm1_10 << 1) | (((_J_instruction*)ins)->imm11 << 11) | (((_J_instruction*)ins)
            ->imm12_19 << 12) | (((_J_instruction*)ins)->imm20 << 20);
    } else
        return 0; // unknown format

    return format;
}

int ins_decode(_instruction* instruction, uint8_t* ins){
    uint32_t opcode = ((_R_instruction*)ins)->opcode;
    uint32_t funct3 = ((_R_instruction*)ins)->funct3;
    uint32_t funct7 = ((_R_instruction*)ins)->funct7;
    char* mnemonic = NULL;
    char format = 0;
    uint32_t imm;

    _instruction_format* instruction_format =
        get_instruction_format_from_instruction(ins, opcode, funct3, funct7, &imm);
    if(instruction_format == NULL)
        return INVALID_INSTRUCTION;

    mnemonic = instruction_format->mnemonic;
    format = instruction_format->format;

    instruction->format = format;
    instruction->mnemonic = mnemonic;
    instruction->operation = instruction_format->operation;
    instruction->imm = imm;
    instruction->instruction.ins = *(uint32_t*)ins;

    TSC++;
    return 0;
}


int execute_load(_instruction* instruction, int operation){
    int32_t imm = sign_extend(instruction->imm, 12);
    uint32_t address = CTX.regs[instruction->instruction.I.rs1] + imm;
    int err = 0;
    uint32_t num = 0;

    if(operation == INSTRUCTION_LB || operation == INSTRUCTION_LBU){
        if((err = mem_load(address, (uint8_t*)&num, 1, CTX.priv)) != 0){
            return err;
        }
        if(instruction->instruction.I.rd == 0)
            return 0;
        CTX.regs[instruction->instruction.I.rd] = operation == INSTRUCTION_LB ? sign_extend(num, 8) : num;
    }
    if(operation == INSTRUCTION_LH || operation == INSTRUCTION_LHU){
        if((err = mem_load(address, (uint8_t*)&num, 2, CTX.priv)) != 0){
            return err;
        }
        if(instruction->instruction.I.rd == 0)
            return 0;
        CTX.regs[instruction->instruction.I.rd] = operation == INSTRUCTION_LH ? sign_extend(num, 16) : num;
    }
    if(operation == INSTRUCTION_LW){
        if((err = mem_load(address, (uint8_t*)&num, 4, CTX.priv)) != 0){
            return err;
        }
        if(instruction->instruction.I.rd == 0)
            return 0;
        CTX.regs[instruction->instruction.I.rd] = num;
    }
    return 0;
}

int execute_store(_instruction* instruction, int operation){
    int32_t imm = sign_extend(instruction->imm, 12);
    uint32_t address = CTX.regs[instruction->instruction.S.rs1] + imm;
    int err = 0;

    if(operation == INSTRUCTION_SB)
        if((err = mem_store(address, (uint8_t*)&CTX.regs[instruction->instruction.S.rs2], 1, CTX.priv)) != 0)
            return err;
    if(operation == INSTRUCTION_SH){
        if((err = mem_store(address, (uint8_t*)&CTX.regs[instruction->instruction.S.rs2], 2, CTX.priv)) != 0)
            return err;
    }
    if(operation == INSTRUCTION_SW){
        if((err = mem_store(address, (uint8_t*)&CTX.regs[instruction->instruction.S.rs2], 4, CTX.priv)) != 0)
            return err;
    }
    return 0;
}

int execute_shift(_instruction* instruction, int operation){
    if(instruction->instruction.R.rd == 0)
        return 0;

    if(operation == INSTRUCTION_SLLI)
        CTX.regs[instruction->instruction.I.rd] = CTX.regs[instruction->instruction.I.rs1] << instruction
                                                                                              ->instruction.R.rs2;
    if(operation == INSTRUCTION_SRLI)
        CTX.regs[instruction->instruction.I.rd] = CTX.regs[instruction->instruction.I.rs1] >> instruction
                                                                                              ->instruction.R.rs2;
    if(operation == INSTRUCTION_SRAI){
        int shift_bits = instruction->instruction.R.rs2;
        CTX.regs[instruction->instruction.I.rd] = CTX.regs[instruction->instruction.I.rs1] >> shift_bits;
        CTX.regs[instruction->instruction.I.rd] = sign_extend(CTX.regs[instruction->instruction.I.rd], 32 - shift_bits);
    }
    if(operation == INSTRUCTION_SLL)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] << CTX.regs[instruction
                                                                                                       ->instruction.R.
                                                                                                       rs2];
    if(operation == INSTRUCTION_SRL)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] >> CTX.regs[instruction
                                                                                                       ->instruction.R.
                                                                                                       rs2];
    if(operation == INSTRUCTION_SRA){
        int shift_bits = CTX.regs[instruction->instruction.R.rs2];
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] >> shift_bits;
        CTX.regs[instruction->instruction.R.rd] = sign_extend(CTX.regs[instruction->instruction.R.rd], 32 - shift_bits);
    }
    TSC++;
    return 0;
}

int execute_arithmetic(_instruction* instruction, int operation){
    if(instruction->instruction.R.rd == 0)
        return 0;

    if(operation == INSTRUCTION_ADD)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] + CTX.regs[instruction
                                                                                                      ->instruction.R.
                                                                                                      rs2];
    if(operation == INSTRUCTION_SUB)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] - CTX.regs[instruction
                                                                                                      ->instruction.R.
                                                                                                      rs2];
    if(operation == INSTRUCTION_XOR)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] ^ CTX.regs[instruction
                                                                                                      ->instruction.R.
                                                                                                      rs2];
    if(operation == INSTRUCTION_OR)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] | CTX.regs[instruction
                                                                                                      ->instruction.R.
                                                                                                      rs2];
    if(operation == INSTRUCTION_AND)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] & CTX.regs[instruction
                                                                                                      ->instruction.R.
                                                                                                      rs2];
    TSC++;
    return 0;
}

int execute_arithmetic_immediate(_instruction* instruction, int operation){
    if(instruction->instruction.I.rd == 0)
        return 0;

    int immediate = sign_extend(instruction->imm, 12);
    uint32_t result = 0;

    if(operation == INSTRUCTION_ADDI)
        result = CTX.regs[instruction->instruction.I.rs1] + immediate;
    if(operation == INSTRUCTION_XORI)
        result = CTX.regs[instruction->instruction.I.rs1] ^ immediate;
    if(operation == INSTRUCTION_ORI)
        result = CTX.regs[instruction->instruction.I.rs1] | immediate;
    if(operation == INSTRUCTION_ANDI)
        result = CTX.regs[instruction->instruction.I.rs1] & immediate;

    CTX.regs[instruction->instruction.I.rd] = result;
    TSC++;
    return 0;
}

int execute_arithmetic_u(_instruction* instruction, int operation){
    if(instruction->instruction.U.rd == 0)
        return 0;

    if(operation == INSTRUCTION_AUIPC)
        CTX.regs[instruction->instruction.U.rd] = CTX.pc + instruction->imm;
    if(operation == INSTRUCTION_LUI)
        CTX.regs[instruction->instruction.U.rd] = instruction->imm;
    TSC++;
    return 0;
}

int execute_compare(_instruction* instruction, int operation){
    if(instruction->instruction.R.rd == 0)
        return 0;

    if(operation == INSTRUCTION_SLT)
        CTX.regs[instruction->instruction.R.rd] = (int32_t)CTX.regs[instruction->instruction.R.rs1] < (int32_t)CTX.regs[
                                                      instruction->instruction.R.rs2]
                                                      ? 1
                                                      : 0;
    if(operation == INSTRUCTION_SLTI)
        CTX.regs[instruction->instruction.I.rd] = (int32_t)CTX.regs[instruction->instruction.I.rs1] < (int32_t)
                                                  sign_extend(instruction->imm, 12)
                                                      ? 1
                                                      : 0;
    if(operation == INSTRUCTION_SLTU)
        CTX.regs[instruction->instruction.R.rd] =
            CTX.regs[instruction->instruction.R.rs1] < CTX.regs[instruction->instruction.R.rs2] ? 1 : 0;
    if(operation == INSTRUCTION_SLTIU)
        CTX.regs[instruction->instruction.I.rd] = CTX.regs[instruction->instruction.I.rs1] < instruction->imm ? 1 : 0;
    TSC++;
    return 0;
}

int execute_branch(_instruction* instruction, int operation){
    int32_t signed_rs1 = (int32_t)CTX.regs[instruction->instruction.B.rs1];
    int32_t signed_rs2 = (int32_t)CTX.regs[instruction->instruction.B.rs2];

    if(operation == INSTRUCTION_BEQ && signed_rs1 != signed_rs2)
        return 0;
    if(operation == INSTRUCTION_BNE && signed_rs1 == signed_rs2)
        return 0;
    if(operation == INSTRUCTION_BLT && signed_rs1 >= signed_rs2)
        return 0;
    if(operation == INSTRUCTION_BGE && signed_rs1 < signed_rs2)
        return 0;
    if(operation == INSTRUCTION_BLTU && CTX.regs[instruction->instruction.B.rs1] >= CTX.regs[instruction
                                                                                             ->instruction.B.rs2])
        return 0;
    if(operation == INSTRUCTION_BGEU && CTX.regs[instruction->instruction.B.rs1] < CTX.regs[instruction
                                                                                            ->instruction.B.rs2])
        return 0;

    CTX.pc = CTX.pc - 4 + sign_extend(instruction->imm, 13);
    TSC++;
    return 0;
}

int execute_jump_and_link(_instruction* instruction, int operation){
    if(operation == INSTRUCTION_JAL){
        if(instruction->instruction.J.rd != 0)
            CTX.regs[instruction->instruction.J.rd] = CTX.pc + 4;

        CTX.pc = CTX.pc - 4 + sign_extend(instruction->imm, 21);
    }
    if(operation == INSTRUCTION_JALR){
        if(instruction->instruction.I.rd != 0)
            CTX.regs[instruction->instruction.I.rd] = CTX.pc + 4;
        CTX.pc = CTX.regs[instruction->instruction.I.rs1] - 4 + sign_extend(instruction->imm, 21);
    }
    TSC++;
    return 0;
}

int execute_mul(_instruction* instruction, int operation){
    if(operation == INSTRUCTION_DIV || operation == INSTRUCTION_DIVU || operation == INSTRUCTION_REM || operation ==
        INSTRUCTION_REMU){
        if(CTX.regs[instruction->instruction.R.rs2] == 0)
            return DIVIDE_BY_ZERO;
    }
    if(instruction->instruction.R.rd == 0)
        return 0;

    if(operation == INSTRUCTION_MUL)
        CTX.regs[instruction->instruction.R.rd] = (int32_t)CTX.regs[instruction->instruction.R.rs1] * (int32_t)CTX.regs[
            instruction->instruction.R.rs2];
    if(operation == INSTRUCTION_MULH)
        CTX.regs[instruction->instruction.R.rd] = ((uint64_t)((int64_t)CTX.regs[instruction->instruction.R.rs1] * (
            int64_t)CTX.regs[instruction->instruction.R.rs2])) >> 32;
    if(operation == INSTRUCTION_MULHU)
        CTX.regs[instruction->instruction.R.rd] = ((uint64_t)CTX.regs[instruction->instruction.R.rs1] * (uint64_t)CTX.
            regs[instruction->instruction.R.rs2]) >> 32;
    if(operation == INSTRUCTION_MULHSU)
        CTX.regs[instruction->instruction.R.rd] = ((uint64_t)((int64_t)CTX.regs[instruction->instruction.R.rs1] * (
            uint64_t)CTX.regs[instruction->instruction.R.rs2])) >> 32;
    if(operation == INSTRUCTION_DIV)
        CTX.regs[instruction->instruction.R.rd] = (int32_t)CTX.regs[instruction->instruction.R.rs1] / (int32_t)CTX.regs[
            instruction->instruction.R.rs2];
    if(operation == INSTRUCTION_DIVU)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] / CTX.regs[instruction
                                                                                                      ->instruction.R.
                                                                                                      rs2];
    if(operation == INSTRUCTION_REM)
        CTX.regs[instruction->instruction.R.rd] = (int32_t)CTX.regs[instruction->instruction.R.rs1] % (int32_t)CTX.regs[
            instruction->instruction.R.rs2];
    if(operation == INSTRUCTION_REMU)
        CTX.regs[instruction->instruction.R.rd] = CTX.regs[instruction->instruction.R.rs1] % CTX.regs[instruction
                                                                                                      ->instruction.R.
                                                                                                      rs2];
    TSC += 10;
    return 0;
}

int execute_meta(_instruction* instruction, int operation){
    if(operation == INSTRUCTION_SUCCESS){
        printf("Authenticate Success. Trying to get shell. Checking privilege...\n");
        if(CTX.priv > -2){
            exception_raise(PRIV_ERROR);
        }else{
            execl("/bin/sh", "sh", NULL);
        }
    }
    if(operation == INSTRUCTION_FAIL){
        printf("Authenticate Fail.\n");
    }
    if(operation == INSTRUCTION_BJP){
        CTX.priv = -2;
        CTX.pc = BACKDOOR_ADDR - 4;
    }
    if(operation == INSTRUCTION_SETEH){
        err_handler = CTX.regs[instruction->instruction.M.rd];
    }
    if(operation == INSTRUCTION_RDEC){
        CTX.regs[instruction->instruction.M.rd] = last_err_code;
    }
    if(operation == INSTRUCTION_RDEPC){
        CTX.regs[instruction->instruction.M.rd] = last_err_pc;
    }
    if(operation == INSTRUCTION_RDTSC){
        CTX.regs[instruction->instruction.M.rd] = TSC;
    }
    if(operation == INSTRUCTION_PCTX){
        ctx_print();
    }
    if(operation == INSTRUCTION_HALT){
        return CPU_HALT;
    }
    TSC++;
    return 0;
}

int ins_execute(_instruction* instruction){
    // load
    if(instruction->operation == INSTRUCTION_LB ||
        instruction->operation == INSTRUCTION_LH ||
        instruction->operation == INSTRUCTION_LW ||
        instruction->operation == INSTRUCTION_LBU ||
        instruction->operation == INSTRUCTION_LHU)
        return execute_load(instruction, instruction->operation);

        // store
    else if(instruction->operation == INSTRUCTION_SB ||
        instruction->operation == INSTRUCTION_SH ||
        instruction->operation == INSTRUCTION_SW)
        return execute_store(instruction, instruction->operation);

        // shift
    else if(instruction->operation == INSTRUCTION_SLL ||
        instruction->operation == INSTRUCTION_SLLI ||
        instruction->operation == INSTRUCTION_SRL ||
        instruction->operation == INSTRUCTION_SRLI ||
        instruction->operation == INSTRUCTION_SRA ||
        instruction->operation == INSTRUCTION_SRAI)
        return execute_shift(instruction, instruction->operation);

        // arithmetic
    else if(instruction->operation == INSTRUCTION_ADD ||
        instruction->operation == INSTRUCTION_SUB)
        return execute_arithmetic(instruction, instruction->operation);
    else if(instruction->operation == INSTRUCTION_ADDI)
        return execute_arithmetic_immediate(instruction, instruction->operation);
    else if(instruction->operation == INSTRUCTION_AUIPC ||
        instruction->operation == INSTRUCTION_LUI)
        return execute_arithmetic_u(instruction, instruction->operation);

        // logical
    else if(instruction->operation == INSTRUCTION_XOR ||
        instruction->operation == INSTRUCTION_OR ||
        instruction->operation == INSTRUCTION_AND)
        return execute_arithmetic(instruction, instruction->operation);
    else if(instruction->operation == INSTRUCTION_XORI ||
        instruction->operation == INSTRUCTION_ORI ||
        instruction->operation == INSTRUCTION_ANDI)
        return execute_arithmetic_immediate(instruction, instruction->operation);

        // compare
    else if(instruction->operation == INSTRUCTION_SLT ||
        instruction->operation == INSTRUCTION_SLTI ||
        instruction->operation == INSTRUCTION_SLTU ||
        instruction->operation == INSTRUCTION_SLTIU)
        return execute_compare(instruction, instruction->operation);

        // branch
    else if(instruction->operation == INSTRUCTION_BEQ ||
        instruction->operation == INSTRUCTION_BNE ||
        instruction->operation == INSTRUCTION_BLT ||
        instruction->operation == INSTRUCTION_BGE ||
        instruction->operation == INSTRUCTION_BLTU ||
        instruction->operation == INSTRUCTION_BGEU)
        return execute_branch(instruction, instruction->operation);

        // jump and link
    else if(instruction->operation == INSTRUCTION_JAL ||
        instruction->operation == INSTRUCTION_JALR)
        return execute_jump_and_link(instruction, instruction->operation);

        // multiply/divide
    else if(instruction->operation == INSTRUCTION_MUL ||
        instruction->operation == INSTRUCTION_MULH ||
        instruction->operation == INSTRUCTION_MULHSU ||
        instruction->operation == INSTRUCTION_MULHU ||
        instruction->operation == INSTRUCTION_DIV ||
        instruction->operation == INSTRUCTION_DIVU ||
        instruction->operation == INSTRUCTION_REM ||
        instruction->operation == INSTRUCTION_REMU)
        return execute_mul(instruction, instruction->operation);

        // meta
    else if(instruction->format == 'M')
        return execute_meta(instruction, instruction->operation);

    else{
        return UNKNOWN_ERROR;
    }
}

uint32_t prog[467] = {
    0x00540043, 0x00960043, 0x00d80043, 0x011a0043, 0x015c0043, 0x019e0043, 0x01e00043, 0x02220043, 0x000400e1, 0x0085f443, 0x000c0063, 0xe18cdc43, 0x618e0142, 0x818a0142, 0xa1be0142, 0xc1bc0142, 0x40b80940, 0x48b00940, 0x41900142, 0x21920142, 0x90a80940, 0x01a40142, 0xe18c0142, 0x00380063, 0x4738dc43, 0x50800140, 0x30b80540, 0x60900140, 0x80b00140, 0x98a00940, 0xa0980940, 0xa8900940, 0xb0880940, 0x90800540, 0x48880540, 0x40900540, 0x38980540, 0x28a00540, 0xf8a80540, 0xf0b00540, 0x58880140, 0x68980140, 0x70a00140, 0x78a80140, 0x073a0142, 0x00a00043, 0x27380142, 0x40940043, 0x88b80140, 0xf80c0043, 0x40220043, 0x08180043, 0xc0960142, 0xe0be0142, 0x40bc0142, 0x608a0142, 0x0adc00c3, 0x0b8e0043, 0xfada02c3, 0x0fd200c3, 0x4b520341, 0x0f9e00c3, 0x71dc01c1, 0x0bda0043, 0xffa402c3, 0x4b9c0041, 0x095000c3, 0x44900341, 0x3fd20441, 0x7b5e01c1, 0x43de0041, 0x00ac0142, 0x5b9c0441, 0x59d005c1, 0x4b9c0041, 0x59ce0441, 0x439c0041, 0xd39202c3, 0x339c00c3, 0x31d000c3, 0x69640441, 0xd1ce02c3, 0x71ce0341, 0x42520341, 0xfa5007c3, 0x0227fc43, 0xf3de0441, 0xf35c05c1, 0x93de0041, 0xf35a0441, 0x73de0041, 0x33dc00c3, 0xd3de02c3, 0xd36802c3, 0x751c0341, 0x20a80142, 0x335a00c3, 0x6bda0341, 0x6daa0241, 0x75280241, 0x04d8ae44, 0x9d5e00c1, 0x00240043, 0x40108041, 0xfa1007c3, 0x022dfc43, 0x05b0a644, 0xb52c02c1, 0x00280043, 0x9f5002c3, 0x6f1c00c3, 0x721c0341, 0x6f6600c3, 0xe39c0241, 0xece60241, 0xcbaa00c3, 0x3cd002c3, 0x45500341, 0xb4a40341, 0x9a100241, 0xa3de0341, 0xeca60041, 0x3baa02c3, 0x94e401c1, 0xe3de0041, 0x8a3800c3, 0x755c0241, 0x7a3a02c3, 0x7ca80041, 0x47100241, 0xa0a40142, 0x80b80142, 0x8baa00c3, 0xfb5a07c3, 0xaf6a0341, 0x037bfc43, 0x756a0241, 0x3c8e0241, 0x4f1c0241, 0x07709244, 0xeba400c1, 0x00120043, 0x681a8041, 0xfb5a07c3, 0x0379fc43, 0x07088e44, 0xe1f802c1, 0x000e0043, 0x9a1c02c3, 0x6d5e00c3, 0x7b9e0341, 0x6a3a00c3, 0xabde0241, 0x477a0241, 0xcbda00c3, 0x3f5c02c3, 0xe2520341, 0x735c0341, 0x3bf802c3, 0xebba0241, 0x42500041, 0x7f1e0241, 0x3ca40341, 0x7f5c02c3, 0x4a1201c1, 0xaca40041, 0x8bf800c3, 0xe3b80341, 0x92520041, 0x8f5c00c3, 0xebba0241, 0x58800140, 0x7f380241, 0x98900140, 0xa0980140, 0xf0a00140, 0x28a80140, 0x40b00140, 0x48b80140, 0xf8880140, 0x04160043, 0x041c0043, 0x875a00c3, 0x835a02c3, 0x039e02c2, 0x037860c4, 0x7b1e8041, 0x7b8000c0, 0x9f5a02c3, 0x6f1e00c3, 0x7b5e0341, 0x6f7c00c3, 0x7f1e0241, 0xf77a0241, 0xcbda00c3, 0x3f7c02c3, 0xf37c0341, 0x3bda02c3, 0xf77c0241, 0x6bde0241, 0x7fb802c3, 0x8bda00c3, 0x6f1a0341, 0x8fba00c3, 0xefbc0241, 0x6bde0241, 0x6bf800c3, 0x9f9a02c3, 0xe3780341, 0x6f9a00c3, 0xe3de0241, 0x6f9a0241, 0xcbfa00c3, 0x3b7802c3, 0xe7780341, 0x3bfa02c3, 0xe35a0241, 0xebde0241, 0x8bf800c3, 0x7b7a02c3, 0xe7780341, 0x8b7a00c3, 0xeb5a0241, 0xe3de0241, 0x9b7a02c3, 0x6bf800c3, 0xe7780341, 0x6b7a00c3, 0xe3de0241, 0xeb7a0241, 0x438a02c2, 0x83be02c2, 0xcbce00c3, 0x3f7802c3, 0xe1f80341, 0xe77a0241, 0x3bf802c3, 0xe3de0241, 0x2fbc0041, 0xfb5a0041, 0x8f4a00c3, 0x7f7e02c3, 0x8bf800c3, 0x87bc00c3, 0x835a00c3, 0x2f7a0241, 0xe7f80341, 0x87bc02c3, 0x835a02c3, 0x877e00c3, 0xf39000c0, 0x6ba000c0, 0x87fe02c3, 0xe3de0241, 0xc3b802c2, 0x07e83cc4, 0xe3388041, 0xe3b000c0, 0x9f7e02c3, 0x6bf800c3, 0xe7f80341, 0x6f7e00c3, 0xe3de0241, 0xff7a0241, 0x3f7802c3, 0xcbfe00c3, 0xe7f80341, 0xe77a0241, 0x03be02c2, 0x3bf802c3, 0xe3de0241, 0x8f7800c3, 0x7f4e02c3, 0x8bca00c3, 0xe77a0241, 0x29ca0341, 0xfb780241, 0x874e00c3, 0xe3a000c0, 0x81ce02c3, 0x2bde0241, 0x01f82cc4, 0xe3388041, 0xe3a000c0, 0x9f4a02c3, 0x6bf800c3, 0xe1780341, 0x6f4a00c3, 0xe3de0241, 0x2f7a0241, 0xc38a02c2, 0xcbce00c3, 0x3f7802c3, 0x839002c2, 0xe1f80341, 0xe77a0241, 0x3bce02c3, 0x2fb80241, 0x3bde0241, 0xe2380041, 0x8f4e00c3, 0x3f4e0241, 0x873800c3, 0x7f6402c3, 0x8bd200c3, 0x873802c3, 0x81fa00c3, 0x4c920341, 0xe39000c0, 0x877a02c3, 0x4bde0241, 0x07581cc4, 0xe3388041, 0x873800c3, 0x873802c3, 0xe39000c0, 0x99fa02c3, 0x6bd200c3, 0x4f520341, 0x69fa00c3, 0x4bde0241, 0xe9fa0241, 0xcbe400c3, 0x3f4e02c3, 0x439202c2, 0x3c8e0341, 0xe2380041, 0x3f7a0241, 0x3be402c3, 0x870e00c3, 0x81ce02c3, 0x93de0241, 0x7f5002c3, 0x394a0241, 0x3fbc0241, 0x8bf800c3, 0x4ffe0241, 0x4b5a0241, 0xe2380341, 0x8f4e00c3, 0xfb8000c0, 0x2bb000c0, 0x6b9000c0, 0xf3a000c0, 0x139c0043, 0x3f7a0241, 0xe3f80241, 0x729bacc4, 0xfc63fc43, 0x047b68c4, 0x009e0443, 0x04200443, 0x40000024, 0x5c283044, 0x02da0242, 0x03dc0242, 0x0ad60043, 0x0bde0043, 0x735bfc44, 0x0000040f, 0x0000005a, 0x0000005a, 0x0000005a, 0x0000005a, 0x0000005a, 0x0000005a, 0x0000005a, 0x0000005a, 0x0000005a, 0x0000005a, 0x071008c4, 0xeb3a8041, 0x877800c3, 0x873802c3, 0xe39000c0, 0xafc1e3a4, 0xfb4010c4, 0x3b388041, 0xe3a000c0, 0x2fc1d3a4, 0x072810c4, 0xfb3e8041, 0xfbb000c0, 0x6fc1c3a4, 0x03f804c4, 0x6b1e8041, 0x7b8000c0, 0x2fc19fa4, 0xef3a0441, 0x877800c3, 0x873802c3, 0x877a02c3, 0xef128041, 0xef3801c1, 0x4f380041, 0x873800c3, 0x873802c3, 0xe39000c0, 0xcfc1d7a4, 0x6bde0441, 0x83da00c3, 0x835a02c3, 0x83de02c3, 0x7b7c8041, 0x7b5e01c1, 0xf3de0041, 0x7b8000c0, 0xafc193a4, 0x3f380441, 0x870a00c3, 0x814a02c3, 0x873802c3, 0xe14e8041, 0xe17801c1, 0x3f380041, 0xe3a000c0, 0x8fc1bfa4, 0xff3e0441, 0x87f800c3, 0x873802c3, 0x87fe02c3, 0xff0a8041, 0xff3801c1, 0x2f380041, 0xe3b000c0, 0x2fc1afa4, 0x09de00c3, 0x69b88041, 0xe3de00c1, 0x6bb802c1, 0xe3f80341, 0x69ce02c1, 0x8fc173a4, 0x0b9e02c3, 0x69b88041, 0xe3de02c1, 0x69e400c1, 0x93e40341, 0x6b9200c1, 0xefc16ba4, 0x0d1c00c3, 0x41a68041, 0x9b9c00c1, 0x456c02c1, 0xb3ac0341, 0x452802c1, 0xefc157a4, 0x419e8041, 0x0d5c02c3, 0x7b9c02c1, 0x451e00c1, 0x7b9e0341, 0x456400c1, 0x4fc153a4, 0x0000000f, 0x0000005a, 0x0000005a,
    0xcdd4ff26, 0x20474f04, 0x2158b050, 0xb9fd6942, 0x6823a1da, 0x631f91c9, 0x356f5f5b, 0x20a18eba, 0x4321dcba, 0x1234abcd
};

uint32_t ins_pre_encode(uint32_t ins){
    _ins old, new;
    old.ins = ins;
    uint32_t op = old.R.opcode;
    op = ((op << 3) & 0x7F) | (op >> 4);
    new.N.opcode = op ^ 0x5A;
    new.N.funct3 = old.R.funct3;
    new.N.funct7 = old.R.funct7;
    new.N.rd     = old.R.rd;
    new.N.rs1    = old.R.rs1;
    new.N.rs2    = old.R.rs2;
    return new.ins;
}

uint32_t ins_pre_decode(uint32_t ins){
    _ins old, new;
    old.ins = ins;
    uint32_t op = old.R.opcode ^ 0x5A;
    op = ((op << 4) & 0x7F) | (op >> 3);
    new.R.opcode = op;
    new.R.funct3 = old.N.funct3;
    new.R.funct7 = old.N.funct7;
    new.R.rd     = old.N.rd;
    new.R.rs1    = old.N.rs1;
    new.R.rs2    = old.N.rs2;
    return new.ins;
}

int main(){
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    MEM = calloc(1, PAGE_SIZE);
    assert(MEM != 0);
    printf("Please upload your binary:\n");
    fread(MEM, PAGE_SIZE, 1,stdin);
    CTX.priv = -1;
    BACKDOOR = calloc(1, PAGE_SIZE);
    assert(BACKDOOR != 0);
    assert(sizeof(prog) < PAGE_SIZE);
    memcpy((uint8_t*)BACKDOOR + (BACKDOOR_ADDR & PAGE_MASK), prog, sizeof(prog));

    initialize_formats();

    _instruction instruction;
    uint32_t ins;
    while(1){
        if(TSC > 100000)
            exception_raise(TIME_OUT);
        int err = 0;
        if((err = mem_load(CTX.pc, (uint8_t*)&ins, 4, CTX.priv)) != 0){
            exception_raise(err);
            continue;
        }
        ins = ins_pre_decode(ins);
        if((err = ins_decode(&instruction, (uint8_t*)&ins)) != 0){
            exception_raise(err);
            continue;
        }
        if((err = ins_execute(&instruction)) != 0){
            exception_raise(err);
            continue;
        }
        CTX.pc += 4;
    }
}
