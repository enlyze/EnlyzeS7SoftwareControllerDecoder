// ENLYZE version of pintool as presented in "sOfT7: Revealing the Secrets of Siemens S7 PLCs"
//
// If this code works, it was written by Colin Finck.
// Otherwise, you are free to call it your own.

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include "pin.H"

const size_t STACK_SIZE = 100 * 1024 * 1024;
const size_t LOWER_ADDRESS_BOUND = 0x2000000000;
const size_t UPPER_ADDRESS_BOUND = 0x3000000000;

const size_t ALLOC_PFN = 0x20000bd5e0;
const size_t SETUP_PFN = 0x20000550a0;
const size_t DECODE_PFN = 0x2000143fc0;

struct CF_DecryptWorkStruct
{
    void* pfnFirstFieldFun;
    unsigned int TotalSizeOfFinalOutputFile;
    unsigned int CurrentOffsetInOutputFile;
    char *pTempBuf;
    unsigned int DecodedBytesInThisIteration;
    unsigned int SomethingElse;
    unsigned int SetToZero1;
    unsigned int SetToZero1_1;
    unsigned int SetToZero2;
    unsigned int OutputChunkBufferSize;
    void* pElfImage;   
    char* pOutputChunkBuffer;
    unsigned int Z11;
    unsigned int Z12;
    unsigned int Z3;
    unsigned int Z4;
    unsigned int CurrentOffsetInOutputChunkBuffer;
    unsigned int Z14;
    unsigned int Z9;
    unsigned int Z10;
    unsigned int TotalDecodedBytes;
    unsigned int OutputChunkBufferSizeAgain;
};

KNOB<std::string> KnobCpuFile(KNOB_MODE_WRITEONCE, "pintool", "c", "", "Path to the encoded cpu.elf file");

ADDRINT g_addrEntry;
char *g_pCpuFile;
unsigned long long g_cbCpuFile;
std::ofstream g_OutputFile;
char *g_pStack;
CF_DecryptWorkStruct *g_pWorkStruct;
unsigned long long g_ReturnValue;


INT32 Usage()
{
    std::cerr << "Runs the code from vmm_2nd_stage.elf to decode the given cpu.elf file" << std::endl
              << "ENLYZE version of pintool as presented in \"sOfT7: Revealing the Secrets of Siemens S7 PLCs\"" << std::endl
              << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

void *MyAlloc(void* unused, unsigned long long cb, unsigned long long unused_value)
{
    std::cout << "[*] Hello from MyAlloc for " << cb << " bytes" << std::endl;

    void* p = malloc(cb);
    memset(p, 0, cb);

    std::cout << "    Allocated @ " << StringFromAddrint((ADDRINT)p) << std::endl;

    return p;
}

VOID ImageLoad(IMG img, VOID* v)
{
    std::cout << "[*] Loading image " << IMG_Name(img).c_str() << " @ " << StringFromAddrint(IMG_StartAddress(img)) << std::endl;

    if (!IMG_IsMainExecutable(img))
    {
        return;
    }

    if (!IMG_IsStaticExecutable(img))
    {
        std::cerr << "Image is not static and can't be the vmm_2nd_stage.elf. Aborted!" << std::endl;
        exit(1);
    }

    g_addrEntry = IMG_EntryAddress(img);
    std::cout << "[*] Entry point @ " << StringFromAddrint(g_addrEntry) << std::endl;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            std::cout << "[*] Routine @ " << StringFromAddrint(RTN_Address(rtn)) << std::endl;
        }
    }
}

UINT64 MyCallback(CF_DecryptWorkStruct* pWorkStruct)
{
    printf("===========================\n");
    std::cout << "[*] Hello from MyCallback" << std::endl;

    printf("pfnFirstFieldFun = %p\n", pWorkStruct->pfnFirstFieldFun);
    printf("TotalSizeOfFinalOutputFile = %08x\n", pWorkStruct->TotalSizeOfFinalOutputFile);
    printf("CurrentOffsetInOutputFile = %08x\n", pWorkStruct->CurrentOffsetInOutputFile);
    printf("pTempBuf = %p\n", pWorkStruct->pTempBuf);
    printf("DecodedBytesInThisIteration = %08x\n", pWorkStruct->DecodedBytesInThisIteration);
    printf("SomethingElse = %08x\n", pWorkStruct->SomethingElse);
    printf("SetToZero1 = %08x\n", pWorkStruct->SetToZero1);
    printf("SetToZero1_1 = %08x\n", pWorkStruct->SetToZero1_1);
    printf("SetToZero2 = %08x\n", pWorkStruct->SetToZero2);
    printf("OutputChunkBufferSize = %08x\n", pWorkStruct->OutputChunkBufferSize);
    printf("pElfImage = %p\n", pWorkStruct->pElfImage);
    printf("pOutputChunkBuffer = %p\n", pWorkStruct->pOutputChunkBuffer);
    printf("Z11 = %08x\n", pWorkStruct->Z11);
    printf("Z12 = %08x\n", pWorkStruct->Z12);
    printf("Z3 = %08x\n", pWorkStruct->Z3);
    printf("Z4 = %08x\n", pWorkStruct->Z4);
    printf("CurrentOffsetInOutputChunkBuffer = %08x\n", pWorkStruct->CurrentOffsetInOutputChunkBuffer);
    printf("Z14 = %08x\n", pWorkStruct->Z14);
    printf("Z9 = %08x\n", pWorkStruct->Z9);
    printf("Z10 = %08x\n", pWorkStruct->Z10);
    printf("TotalDecodedBytes = %08x\n", pWorkStruct->TotalDecodedBytes);
    printf("OutputChunkBufferSizeAgain = %08x\n", pWorkStruct->OutputChunkBufferSizeAgain);

    std::cout << "[*] Saving " << pWorkStruct->DecodedBytesInThisIteration << " bytes for this chunk" << std::endl;

    // pOutputChunkBuffer is used like a ring buffer.
    // We have to check if it overflowed.
    unsigned int Start = pWorkStruct->CurrentOffsetInOutputFile % pWorkStruct->OutputChunkBufferSize;
    unsigned int End = std::min(Start + pWorkStruct->DecodedBytesInThisIteration, pWorkStruct->OutputChunkBufferSize);
    unsigned int cb = End - Start;
    g_OutputFile.write(&pWorkStruct->pOutputChunkBuffer[Start], cb);

    if (Start + pWorkStruct->DecodedBytesInThisIteration > pWorkStruct->OutputChunkBufferSize)
    {
        // It overflowed. Write the other part as well.
        Start = 0;
        End = pWorkStruct->CurrentOffsetInOutputChunkBuffer;
        cb = End - Start;
        g_OutputFile.write(&pWorkStruct->pOutputChunkBuffer[Start], cb);
    }

    if (pWorkStruct->TotalDecodedBytes == pWorkStruct->TotalSizeOfFinalOutputFile)
    {
        std::cout << "[*] Finished successfully" << std::endl;
        exit(0);
    }

    return 0;
}

void MyEntryPoint()
{
    std::cout << "[*] Hello from MyEntryPoint" << std::endl;

    // Set up the work struct.
    {
        CONTEXT ctxt = {};
        char *pRsp = g_pStack + STACK_SIZE / 2;
        PIN_SetContextRegval(&ctxt, REG_RSP, (const UINT8 *)&pRsp);

        std::cout << "[*] Calling Decrypt_SetupStruct" << std::endl;
        PIN_CallApplicationFunction(&ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, (AFUNPTR)SETUP_PFN, nullptr,
                                    PIN_PARG(unsigned long long *), &g_ReturnValue,
                                    PIN_PARG(void *), g_pWorkStruct,
                                    PIN_PARG_END());
    }

    // Perform the decoding.
    {
        CONTEXT ctxt = {};
        char *pRsp = g_pStack + STACK_SIZE / 2;
        PIN_SetContextRegval(&ctxt, REG_RSP, (const UINT8 *)&pRsp);

        std::cout << "[*] Calling Decrypt_Do" << std::endl;
        PIN_CallApplicationFunction(&ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, (AFUNPTR)DECODE_PFN, nullptr,
                                    PIN_PARG(unsigned long long *), &g_ReturnValue,
                                    PIN_PARG(void *), g_pWorkStruct,
                                    PIN_PARG(char *), g_pCpuFile,
                                    PIN_PARG(unsigned long long), g_cbCpuFile,
                                    PIN_PARG(char *), g_pWorkStruct->pTempBuf,
                                    PIN_PARG(unsigned long long), 0x1000,
                                    PIN_PARG(void *), MyCallback,
                                    PIN_PARG_END());
    }
}

void TraceInstruction(std::string *pstrTrace)
{
    std::cout << *pstrTrace << std::endl;
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addrIns = INS_Address(ins);
    std::string strTrace = StringFromAddrint(addrIns) + ": " + INS_Disassemble(ins);

    if (addrIns < LOWER_ADDRESS_BOUND || addrIns > UPPER_ADDRESS_BOUND)
    {
        // We only want to instrument the VMM image, not our own code when jumping to it.
        return;
    }

    if (addrIns == g_addrEntry)
    {
        std::cout << strTrace << " --> calling MyEntryPoint instead" << std::endl;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MyEntryPoint, IARG_END);
    }
    else if (addrIns == ALLOC_PFN)
    {
        std::cout << strTrace << " --> jumping to MyAlloc instead" << std::endl;
        INS_InsertDirectJump(ins, IPOINT_BEFORE, (ADDRINT)MyAlloc);
    }
    else
    {
        // Uncomment this to trace every instruction (heavy!)
        //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TraceInstruction, IARG_PTR, new std::string(strTrace), IARG_END);
    }
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    // Read the CPU file.
    std::string strCpuFile = KnobCpuFile.Value();
    if (strCpuFile.empty())
    {
        return Usage();
    }

    std::ifstream CpuFile(strCpuFile);
    if (!CpuFile)
    {
        std::cerr << "Cannot open " << strCpuFile << std::endl;
        return 1;
    }

    CpuFile.seekg(0, std::ios::end);
    g_cbCpuFile = CpuFile.tellg();
    CpuFile.seekg(0, std::ios::beg);

    g_pCpuFile = (char *)malloc(g_cbCpuFile);
    CpuFile.read(g_pCpuFile, g_cbCpuFile);

    std::cout << "[*] Read " << g_cbCpuFile << " VMM bytes to decode @ " << StringFromAddrint((ADDRINT)g_pCpuFile) << std::endl;

    // Create the output file.
    std::string strOutputFile = strCpuFile + ".decoded";
    g_OutputFile.open(strOutputFile);
    if (!g_OutputFile)
    {
        std::cerr << "Cannot open " << strOutputFile << " for writing!" << std::endl;
        return 1;
    }

    // Adjust inputs for the function we want to call.
    g_pCpuFile += 4;
    g_cbCpuFile -= 4;

    UINT8 Skip = (UINT8)*g_pCpuFile;
    g_pCpuFile += Skip;
    g_cbCpuFile -= Skip;

    // Prepare the buffers we need.
    g_pStack = (char*)malloc(STACK_SIZE);
    memset(g_pStack, 0, STACK_SIZE);
    std::cout << "[*] Allocated g_pStack @ " << StringFromAddrint((ADDRINT)g_pStack) << std::endl;

    g_pWorkStruct = (CF_DecryptWorkStruct*)malloc(sizeof(CF_DecryptWorkStruct));
    memset(g_pWorkStruct, 0, sizeof(CF_DecryptWorkStruct));
    std::cout << "[*] Allocated g_pWorkStruct @ " << StringFromAddrint((ADDRINT)g_pWorkStruct) << std::endl;

    g_ReturnValue = 0;

    // Instrument.
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();

    return 0;
}
