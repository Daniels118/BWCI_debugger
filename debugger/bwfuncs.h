#pragma once

#include <Windows.h>
#include <cstdint>

/*
	this file contains pointers to all functions
*/


// simple thing to compile for either bw1 or creature isle
#define GAME_BLACKANDWHITE
// #define GAME_CREATUREISLE

#ifdef GAME_BLACKANDWHITE


//
int(__thiscall* GGame__LoadScriptLibrary)(void* _this, int a2) = (int(__thiscall*)(void*, int)) 0x007C5600;

void(__thiscall* GGame__ClearMap)(void*) = (void(__thiscall*)(void*))(0x005670A0);

struct Game {};
Game* GetGame() { return (Game*)(0x00D7B614); }

void(__thiscall* GGame__StartGame)(Game*) = (void(__thiscall*)(Game*))(0x00560A10);

void(__thiscall* GGame__Loop)(void*) = (void(__thiscall*)(void*))(0x005617D0);

bool(__thiscall* IsMultiplayerGame)(Game*) = (bool(__thiscall*)(Game*))(0x005674C0);

Game* (__thiscall* GScript__Reset)(DWORD*, int) = (Game * (__thiscall*)(DWORD*, int))(0x00700220);

char(__thiscall* BWCheckFeatureIsEnabled)(char*) = (char(__thiscall*)(char*))(0x0053A3B0);
bool(__thiscall* GSetup__LoadMapScript)() = (bool(__thiscall*)())(0x00715080);

signed int(__thiscall* GGame__Init)(void*) = (signed int(__thiscall*)(void*))(0x00563AA0);


int(__cdecl* _SaveAllMap)(char* lpFilename) = (int(__cdecl*)(char* lpFilename))(0x00733940);
int(__cdecl* _SaveLandOnDisk)(char* lpFilename) = (int(__cdecl*)(char* lpFilename))(0x0081E560);


void(__thiscall* PauseGame)(int num) = (void(__thiscall*)(int num))(0x0055F7E0); //sub_55F7E0



void(__thiscall* GGame_ProcessKey)(unsigned __int8*, int, int) = (void(__thiscall*)(unsigned __int8*, int, int))(0x00654F80); //sub_55F7E0

int(__thiscall* Creature__Create)(int* a1, int a2, int a3, int a4) = (int(__thiscall*)(int* a1, int a2, int a3, int a4))(0x0047EDA0); //sub_55F7E0


int(__thiscall* Process3DEngine)(BYTE*) = (int(__thiscall*)(BYTE*))(0x00562310);

//void(__thiscall* Process3DEngine)(void*, int, int) = (void(__thiscall*)(void*, int, int))(0x0054D850);

int(__thiscall* ControlMap__ProcessActionsPerformed)(DWORD*) = (int(__thiscall*)(DWORD*))(0x0047A6B0);

typedef struct TownCentre
{
	char padding[4];
	int32_t colour;
} TownCentre;


////////////////////////////////////////////////////////

// .text:00886DE0 ; signed int __cdecl ciProcessServerMessage(void *chat, ciServerMessage *message)

#elif GAME_CREATUREISLE

// define creature isle function pointers here

#endif