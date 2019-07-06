# R3CPU Design Document (Leaked)

## Introduction
r3cpu is a 32bit RISC CPU developed secretly by team r3kapig. It aims at security and confidentiality. The ISA of this CPU is not released. So we can safely write programs on it without worrying about reverse-engineering! XD

360 is r3cpu's first customer. To test its security, we are invited to put a simple simulator of r3cpu on the WCTF platform. Anyone can upload any binary program and r3cpu will run it remotely.

Like many other CPU vendors, we also put a backdoor in r3cpu without telling anyone. BUT what can those hackers do? They are used to believe what CPU vendors told them. Now that we tell them nothing, they must be blindly desperate! XD

However, one of the r3kapig team member ignorantly used a anti-virus software which uploaded this design document to the cloud database. Boom! The design document of r3cpu is thus leaked (just like IDA 7.2).

Fortunately, the detailed ISA document still remains as a secret. Maybe nobody can break into the backdoor without that (hopefully).

## Memory
We know little about r3cpu MMU: Page size? Endianness? Nothing.

All we currently know is that r3cpu uses protection mode for memory. According to the partial-leaked source code of the simulator, there are two and only two hardcoded pages mapped: one is at 0x0, the other is at an unknown address. The backdoor instruction will jump there and executing code in that page.

## Register
### General registers
There are 32 general registers in r3cpu. Namely r0-r31.

r0 is hardwired to 0. Any write to r0 will be ignored.

### Special registers
PC is not a general register. Only a few instruction can interact with PC, e.g. jump, call, ret, and a instruction which can get a relative address of pc.

There are several special registers that can be read or written by special instructions:

TSC: Time stamp counter, can be read by RDTSC. The cycle is not accurate. However when TSC > 100000 r3cpu will raise a TIMEOUT exception to prevent infinite loop. (No one can solve the halting problem, can they?)

LEC: Last error code, when a exception is raised and handled by exception handler, the LEC register is set to corresponding error code. You can use RDLEC to read it.

LEPC: Last error pc, when the exception is raised, this register is set to the address of the instruction caused the exception. Can be read by RDLEPC.

EHA: Error handler address. Default to -1(0xFFFFFFFF). Can be written by SETEHA. When the exception is raised, r3cpu will check the EHA, if it's not -1, r3cpu will set pc to EHA. So do not set EHA to an unmapped address, or r3cpu will be trapped in exceptions. ;-)

## Instruction
All instructions are 32bit. They all share a similar format (This is a RISC CPU, bro!). Below is the possible positions of opcode, rd, rs1, rs2 and immediate number:

All instructions has the 7bit opcode:
```
31                               0
=========================|=======|
                          opcode
```

Some instructions have 3 additional bits opcode:
```
31                               0
======================|===|=======
                       op3
```

Some instructions have another 7 additional bits opcode:
```
31                               0
===============|=======|==========
                  op7
```

Destination register rd:
```
31                               0
==========|=====|=================
            rd
```

Source registers rs1, rs2:
```
31                               0
=====|=====|======================
 rs2   rs1
```

The immediate number has several possible kinds of positions:
```
31                                   0
===== |==========| ======= |==========
i[4:0]             i[11:5]

31                               0
===== |===========================
i[4:0]

31                                    0
==========| ===== | ======= |==========
            i[4:0]  i[11:5]

31                                         0
========== |=====| ======= |   ===  |=======
  i[24:15]        i[31:25]  i[14:12]

31                                                  0
==========| ==== |   =   |   =   | ====== |==========
           i[4:1]  i[11]   i[12]  i[10:5]

31                                                          0
====   |  =  |  =====  |=====|  =  | ====== |   ===  |=======
i[4:1]  i[11]  i[19:15]       i[20]  i[10:5] i[14:12]
```

Instructions do not touch memory except 5 load instructions and 3 store instructions.

There are no more than 50 instructions in total. Most of them are basic instructions. There are only 9 special instructions:

SETEHA: set exception handler

RDLEC: read exception code

RDLEPC: read exception address

RDTSC: read time stamp

BACKDOOR: GO BACKDOOR!

PRINTCTX: print r0-r31 and pc

HALT: halt the CPU

SUCCESS: print success, and get shell if in privileged mode otherwise raise a PRIV_ERROR

FAIL: print fail

## Backdoor
If BACKDOOR instruction is executed, the privilege level of the context will be lifted and the backdoor code will be run.

The backdoor code will check r1-r8 as password for authentication. Once authenticated, a SUCCESS instruction will be executed. Otherwise a FAIL instruction is executed instead.

## Partial leaked source code
Here is the source code of simulator (not complete):
```c
#define PAGE_FAULT          (-1)
#define PRIV_ERROR          (-2)
#define INVALID_INSTRUCTION (-3)
#define DIVIDE_BY_ZERO      (-4)
#define TIME_OUT            (-101)
#define CPU_HALT            (-102)
#define UNKNOWN_ERROR       (-1111)

struct ctx {
    uint32_t regs[32];
    uint32_t pc;
    int priv;
} CTX;

uint32_t TSC;
uint32_t err_handler = (uint32_t)-1;
uint32_t last_err_code;
uint32_t last_err_pc;

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

int execute_backdoor(instruction* instruction, int operation){
    if(operation == INSTRUCTION_BACKDOOR){
        CTX.priv = -1;
        CTX.pc = BACKDOOR_ADDR - 4; // compensate for CTX.pc+=4
    }
    if(operation == INSTRUCTION_FAIL){
        printf("Authenticate Fail.\n");
    }
    if(operation == INSTRUCTION_SUCCESS){
        printf("Authenticate Success. Trying to get shell. Checking privilege...\n");
        if(CTX.priv > -1){
            exception_raise(PRIV_ERROR);
        }
        execl("/bin/sh", "sh", NULL);
    }
}

int main(){
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    MEM = calloc(1, PAGE_SIZE);
    assert(MEM != 0);
    printf("Please upload your binary:\n");
    fread(MEM, PAGE_SIZE, 1,stdin);
    BACKDOOR = calloc(1, PAGE_SIZE);
    assert(BACKDOOR != 0);
    assert(sizeof(prog) < PAGE_SIZE);
    memcpy((uint8_t*)BACKDOOR + (BACKDOOR_ADDR & PAGE_MASK), backdoor_prog, sizeof(backdoor_prog));

    instruction instruction;
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

```
