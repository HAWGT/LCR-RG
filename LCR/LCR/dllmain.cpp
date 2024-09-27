#include "Utils.h"
#include <nlohmann/json.hpp>

typedef void(__fastcall* TArrayResizeGrow_t)(TArray<FString>& out, int32_t size);
TArrayResizeGrow_t TArrayResizeGrow;

typedef void(__fastcall* FString_t)(FString& a1, const char* Str);
FString_t FString_Init;

void __fastcall hk_GetValidTargetPlatforms(TArray<FString>& out)
{
    std::vector<FString> Costumes;
    TArray<FString> CostumesTArray;

    std::string target_extension = ".json";

    const std::filesystem::path CostumesPath = L"../../Content/Costumes/";

    for (const std::filesystem::directory_entry& entry : std::filesystem::recursive_directory_iterator(CostumesPath))
    {
        if (entry.path().extension() != target_extension)
        {
           continue;
        }

        std::ifstream CostumeInfoFile(entry.path().c_str());

        if (CostumeInfoFile.is_open())
        {
            nlohmann::json Data = nlohmann::json::parse(CostumeInfoFile);

            if (Data["name"].is_string() && Data["guid"].is_string() && Data["type"].is_string() && Data["category"].is_string() && Data["battleMesh"].is_string() && Data["cineMesh"].is_string())
            {
                std::string JName, JGUID, JType, JCategory, JBattleMesh, JCineMesh;
                FString Name, GUID, Type, Category, BattleMesh, CineMesh;

                //lib things
                JName = Data["name"];
                JGUID = Data["guid"];
                JType = Data["type"];
                JCategory = Data["category"];
                JBattleMesh = Data["battleMesh"];
                JCineMesh = Data["cineMesh"];

                //Need to use the internal FString constructor because UE will call FMemory::Free and the pointer needs to be stored internally
                FString_Init(Name, JName.c_str());
                FString_Init(GUID, JGUID.c_str());
                FString_Init(Type, JType.c_str());
                FString_Init(Category, JCategory.c_str());
                FString_Init(BattleMesh, JBattleMesh.c_str());
                FString_Init(CineMesh, JCineMesh.c_str());

                Costumes.push_back(Name);
                Costumes.push_back(GUID);
                Costumes.push_back(Type);
                Costumes.push_back(Category);
                Costumes.push_back(BattleMesh);
                Costumes.push_back(CineMesh);
            }
        }
    }

    int Counter = out.Count;

    for (const auto& Costume : Costumes)
    {
        out.Count = out.Count + 1;

        if (out.Count > out.Max)
        {
            TArrayResizeGrow(out, out.Count);
        }

        out.Data[Counter].Data = Costume.Data;
        out.Data[Counter].Count = Costume.Count;
        out.Data[Counter].Max = Costume.Max;

        ++Counter;
    }
}

void Setup()
{
    BYTE* Orig_GetValidTargetPlatforms = PatternScan("48 89 5C 24 08 57 48 83 EC ? 48 8B D9 48 8D 15 ? ? ? ? 48 8D 4C 24 20");
    FString_Init = reinterpret_cast<FString_t>(PatternScan("48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC ? 33 ED 48 8B DA 48 89 29"));
    TArrayResizeGrow = reinterpret_cast<TArrayResizeGrow_t>(GetAddressFromInstruction((uintptr_t)Orig_GetValidTargetPlatforms + 0x32, 5));

    if (!Orig_GetValidTargetPlatforms || !FString_Init || !TArrayResizeGrow)
    {
        return;
    }

    Detour64(Orig_GetValidTargetPlatforms, (BYTE*)hk_GetValidTargetPlatforms, 13);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Setup, hModule, 0, nullptr);
        /*
        auto CreateConsole = [](const char* name) {
            FILE* ConsoleIO;
            if (!AllocConsole())
                return;
            freopen_s(&ConsoleIO, "CONIN$", "r", stdin);
            freopen_s(&ConsoleIO, "CONOUT$", "w", stderr);
            freopen_s(&ConsoleIO, "CONOUT$", "w", stdout);
            SetConsoleTitleA(name);
            };
        CreateConsole("LCR");
        */
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}