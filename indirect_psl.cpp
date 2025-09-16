#pragma comment(linker, "/subsystem:windows")
#pragma comment(linker, "/entry:Go")
#pragma comment(linker, "/nodefaultlib")

#include "manual_defs.h"

// ... [All previous code remains the same] ...

// --- Entry Point ---
extern "C" void Go() {
    // Core::Init();
    // AddToStartup();
    // SpoofProcess();
    // if (Core::g_ExitProcess) {
    //     Core::g_ExitProcess(0);
    // }
}
