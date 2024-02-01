#pragma once

#include <iostream>

#include <Windows.h>

#include <string>
#include <vector>
#include <list>
#include <unordered_set>
#include <unordered_map>
#include <sstream>

#include "ScriptLibraryR.h"

#undef __FILENAME__
#undef LOG_LEVEL
#undef PAUSE_ON
#define __FILENAME__ "CHLFile.h"
#define LOG_LEVEL 4
#define PAUSE_ON 0
#include "logger.h"

class CHLFile;
class CHLHeader;
class GlobalVariables;
class AutoStartScripts;
class Scripts;
class DataSection;
class TaskVars;
class InitGlobals;

class Struct {
public:
	virtual int getLength() = 0;
	virtual bool read(FILE* file) = 0;

	static const std::string readZString(FILE* file) {
		std::stringstream buf;
		int b = fgetc(file);
		while (b != 0 && b != EOF) {
			buf.put((char)b);
			b = fgetc(file);
		}
		TRACE("  %s", buf.str().c_str());
		return buf.str();
	}

	static std::vector<std::string> readZStringArray(FILE* file) {
		std::vector<std::string> res;
		size_t count;
		size_t n = fread(&count, 4, 1, file);
		if (n < 1) return res;
		if (count > 0) {
			res.reserve(count);
			for (size_t i = 0; i < count; i++) {
				std::string v = readZString(file);
				res.push_back(v);
			}
		}
		return res;
	}

	static int getZStringArraySize(std::vector<std::string>& strings) {
		int l = 4;
		for (auto s : strings) {
			l += s.length() + 1;
		}
		return l;
	}
};

class CHLHeader : Struct {
public:
	char magic[4] = {'L', 'H', 'V', 'M'};
	int version = 8;

	int getLength() {
		return 8;
	}

	bool read(FILE* file) {
		size_t n = fread(magic, 1, 4, file);
		if (n < 4) return false;
		if (strncmp(magic, "LHVM", 4) != 0) {
			ERR("wrong magic string");
			return false;
		}
		n = fread(&version, 4, 1, file);
		if (n < 1) return false;
		if (version != 8) {
			ERR("wrong version");
			return false;
		}
		TRACE("LHVM version 8");
		return true;
	}
};

class GlobalVariables : Struct {
public:
	std::vector<std::string> names;

	int getLength() {
		return getZStringArraySize(names);
	}

	bool read(FILE* file) {
		this->names = readZStringArray(file);
		TRACE("%i global vars", names.size());
		return true;
	}

	int getId(const char* name) const {
		int id = 0;
		for (std::string tName : names) {
			if (tName == name) {
				return id;
			}
			id++;
		}
		return -1;
	}
};

class AutoStartScripts : Struct {
public:
	std::vector<int> items;

	int getLength() {
		return 4 + 4 * items.size();
	}

	bool read(FILE* file) {
		items.clear();
		size_t count;
		size_t n = fread(&count, 4, 1, file);
		if (n < 1) return false;
		if (count > 0) {
			items.resize(count);
			n = fread(&items[0], 4, count, file);
			if (n < count) return false;
		}
		TRACE("%i autostart scripts", items.size());
		return true;
	}
};

class UScript : Struct {
public:
	CHLFile* chl = NULL;

	std::string name = "";
	std::string sourceFilename = "";
	int scriptType = 0;
	int globalCount = 0;
	std::vector<std::string> variables;
	int instructionAddress = 0;
	int parameterCount = 0;
	int scriptID = 0;

	int getLength() {
		return 	  name.length() + 1
			+ sourceFilename.length() + 1
			+ 4 //scriptType
			+ 4 //varOffset
			+ getZStringArraySize(variables)
			+ 4 //instructionAddress
			+ 4 //parameterCount
			+ 4;//scriptID
	}

	bool read(FILE* file) {
		name = readZString(file);
		TRACE("script '%s'", name.c_str());
		sourceFilename = readZString(file);
		TRACE("  in '%s'", sourceFilename.c_str());
		size_t n = fread(&scriptType, 4, 1, file);
		if (n < 1) return false;
		n = fread(&globalCount, 4, 1, file);
		if (n < 1) return false;
		variables = readZStringArray(file);
		TRACE("  %i local vars", variables.size());
		n = fread(&instructionAddress, 4, 1, file);
		if (n < 1) return false;
		TRACE("  instruction address: %i", instructionAddress);
		n = fread(&parameterCount, 4, 1, file);
		if (n < 1) return false;
		TRACE("  %i parameters", parameterCount);
		n = fread(&scriptID, 4, 1, file);
		if (n < 1) return false;
		TRACE("  ID: %i", scriptID);
		return true;
	}

	bool isGlobalVar(int varId) const;
	bool isLocalVar(int varId) const;
	std::string getLocalVar(int varId) const;
	std::string getGlobalVar(int varId) const;
	std::string getVar(int varId) const;
	int getInstructionsCount() const;
	std::list<int>::const_iterator getFirstStringInstruction() const;
	void finalize();
	bool operator==(UScript const& other) const;

private:
	int lastInstructionAddress = -1;
};

class Scripts : Struct {
public:
	CHLFile* chl;

	std::vector<UScript> items;

	Scripts(CHLFile* chl) {
		this->chl = chl;
	}

	int getLength() {
		int l = 4;
		for (auto item : items) {
			l += item.getLength();
		}
		return l;
	}

	bool read(FILE* file) {
		size_t count;
		size_t n = fread(&count, 4, 1, file);
		if (n < 1) return false;
		TRACE("%i scripts", count);
		if (count > 0) {
			items.resize(count);
			for (size_t i = 0; i < count; i++) {
				items[i].chl = this->chl;
				if (!items[i].read(file)) {
					return false;
				}
				items[i].finalize();
			}
		}
		return true;
	}

	UScript* getScriptById(int id) {
		if (id > 0 && id <= (int)items.size()) {
			return &items[id - 1];
		}
		return NULL;
	}

	UScript* findScript(std::string name) {
		for (UScript& script : items) {
			if (script.name == name) {
				return &script;
			}
		}
		return NULL;
	}
};

class DataSection : Struct {
public:
	size_t size = 0;
	char* data = NULL;

	DataSection() {}

	~DataSection() {
		if (managed) {
			free(data);
			data = NULL;
			size = 0;
		}
	}

	int getLength() {
		return 4 + size;
	}

	bool read(FILE* file) {
		managed = true;
		size_t n = fread(&size, 4, 1, file);
		if (n < 1) return false;
		TRACE("data section is %u bytes", size);
		if (size > 64 * 1024 * 1024) {
			ERR("data section is too large (%u bytes)", size);
			return false;
		} else if (size > 0) {
			#pragma warning( push )
			#pragma warning( disable : 6029 )
			data = (char*)malloc(size);
			if (data == NULL) {
				ERR("failed to allocate %u bytes", size);
				return false;
			}
			n = fread(data, 1, size, file);
			#pragma warning( pop )
			if (n < size) return false;
#if LOG_LEVEL >= LL_TRACE
			for (auto str : getStrings()) {
				TRACE("data: '%s'\n", str.c_str());
			}
#endif
		}
		return true;
	}

	int findString(const std::string str) {
		if (cache.empty()) {
			initCache();
		}
		if (cache.contains(str)) {
			return cache[str];
		}
		return -1;
	}

	const char* findByPrefix(const std::string prefix, const char* after) {
		size_t offset = 0;
		while (offset < size) {
			std::string str = std::string(data + offset);
			if (data + offset > after && str.starts_with(prefix)) {
				return data + offset;
			}
			offset += str.length() + 1;
		}
		return NULL;
	}

	const char* getString(size_t offset) const {
		if (offset < 0 || offset >= size) return NULL;
		if (offset > 0 && data[offset - 1] != 0) return NULL;
		return &data[offset];
	}

	std::unordered_set<std::string> getStrings() {
		std::unordered_set<std::string> res;
		size_t offset = 0;
		while (offset < size) {
			const char* str = data + offset;
			res.insert(str);
			offset += strlen(str) + 1;
		}
		return res;
	}

	bool isManaged() {
		return managed;
	}

private:
	bool managed = false;
	std::unordered_map<std::string, int> cache;

	void initCache() {
		size_t offset = 0;
		while (offset < size) {
			std::string str = std::string(data + offset);
			cache[str] = offset;
			offset += str.length() + 1;
		}
	}
};

class TaskVars : Struct {
public:
	int count = 0;
	std::vector<TaskVar> items;

	int getLength() {
		return 4100;
	}

	bool read(FILE* file) {
		size_t n = fread(&count, 4, 1, file);
		if (n < 1) return false;
		items.resize(512);
		n = fread(&items[0], sizeof(TaskVar), 512, file);
		if (n < 512) return false;
		return true;
	}
};

class InitGlobal: Struct {
public:
	int type = 0;
	FLOAT floatVal = 0.0;
	std::string name = "";

	int getLength() {
		return 4 + 4 + name.length() + 1;
	}

	bool read(FILE* file) {
		size_t n = fread(&type, 4, 1, file);
		if (n < 1) return false;
		n = fread(&floatVal, 4, 1, file);
		if (n < 1) return false;
		name = readZString(file);
		return true;
	}
};

class InitGlobals : Struct {
public:
	std::vector<InitGlobal> items;

	int getLength() {
		int l = 4;
		for (auto item : items) {
			l += item.getLength();
		}
		return l;
	}

	bool read(FILE* file) {
		size_t count;
		size_t n = fread(&count, 4, 1, file);
		if (n < 1) return false;
		TRACE("InitGlobals has %i items", count);
		if (count > 0) {
			items.resize(count);
			for (size_t i = 0; i < count; i++) {
				if (!items[i].read(file)) {
					return false;
				}
			}
		}
		return true;
	}

	InitGlobal* get(std::string name) {
		for (auto& var : items) {
			if (var.name == name) {
				return &var;
			}
		}
		return NULL;
	}
};

class CHLFile {
public:
	CHLHeader header;
	GlobalVariables globalVariables;
	InstructionVector instructions{NULL, NULL, NULL};
	AutoStartScripts autoStartScripts;
	Scripts scriptsSection{this};
	DataSection data;
	TaskVars taskVars;
	InitGlobals initGlobals;

	CHLFile() {}

	~CHLFile() {
		if (managed) {
			free(instructions.pFirst);
			instructions.pFirst = 0;
			instructions.pEnd = 0;
			instructions.pBufferEnd = 0;
		}
	}

	bool read(const char* filename) {
		TRACE("reading CHL from '%s'", filename);
		managed = true;
		FILE* file = fopen(filename, "rb");
		if (file == NULL) return false;
		bool res = false;
		do {
			if (!header.read(file)) break;
			if (!globalVariables.read(file)) break;
			if (!readCode(file)) break;
			if (!autoStartScripts.read(file)) break;
			if (!scriptsSection.read(file)) break;
			if (!data.read(file)) break;
			if (!taskVars.read(file)) break;
			if (!initGlobals.read(file)) break;
			res = true;
		} while (false);
		fclose(file);
		return res;
	}

	std::unordered_set<std::string> getSourceFilenames() const {
		std::unordered_set<std::string> res;
		std::string prev = "";
		for (UScript script : scriptsSection.items) {
			std::string& scrName = script.sourceFilename;
			if (scrName != prev) {
				res.insert(scrName);
				prev = scrName;
			}
		}
		return res;
	}

	std::list<int>& getStringInstructions() {
		if (stringInstructions.empty()) {
			const char* prop = data.findByPrefix("string_instructions=", 0);
			if (prop == NULL) {
				WARNING("property 'string_instructions' not found");
			}
			while (prop != NULL) {
				const char* next = data.findByPrefix("string_instructions=", prop);
				const char* p0 = strchr(prop, '=') + 1;
				while (*p0 != 0) {
					const char* p1 = strchr(p0, ',');
					if (p1 == NULL) p1 = p0 + strlen(p0);
					if (p1 - p0 > 0) {
						int instr = atoi(p0);
						TRACE("string instruction: %i", instr);
						stringInstructions.push_back(instr);
					}
					if (*p1 == 0) break;
					p0 = p1 + 1;
				}
				prop = next;
			}
		}
		return stringInstructions;
	}

	bool isManaged() {
		return managed;
	}

private:
	bool managed = false;
	std::list<int> stringInstructions;

	bool readCode(FILE* file) {
		size_t count;
		size_t n = fread(&count, 4, 1, file);
		if (n < 1) return false;
		TRACE("total instructions: %i", count);
		const size_t bytes = sizeof(Instruction) * count;
		instructions.pFirst = (Instruction*)malloc(bytes);
		if (instructions.pFirst == NULL) {
			ERR("failed to allocate %i bytes", bytes);
			return false;
		}
		instructions.pEnd = instructions.pFirst + count;
		instructions.pBufferEnd = instructions.pFirst + count;
		n = fread(instructions.pFirst, sizeof(Instruction), count, file);
		if (n < count) return false;
		return true;
	}
};

class Diff {
public:
	std::unordered_set<std::string> added;
	std::unordered_set<std::string> removed;
	std::unordered_set<std::string> changed;
};

class CHLDiff {
public:
	CHLFile* file1;
	CHLFile* file2;

	Diff globalVars;
	Diff scripts;
	Diff sources;
	Diff data;
	Diff autostartScripts;

	CHLDiff(CHLFile* file1, CHLFile* file2) {
		this->file1 = file1;
		this->file2 = file2;
		std::unordered_set<std::string> files1 = file1->getSourceFilenames();
		std::unordered_set<std::string> files2 = file2->getSourceFilenames();
		//globalVars
		std::unordered_map<std::string, int> vars1;
		std::unordered_map<std::string, int> vars2;
		std::string lastName = "";
		for (auto name : file1->globalVariables.names) {
			if (name == "LHVMA") {
				vars1[lastName]++;
			} else {
				vars1[name] = 1;
				lastName = name;
			}
		}
		for (auto name : file2->globalVariables.names) {
			if (name == "LHVMA") {
				vars2[lastName]++;
			} else {
				vars2[name] = 1;
				lastName = name;
			}
		}
		for (auto var1 : vars1) {
			if (!vars2.contains(var1.first)) {
				globalVars.removed.insert(var1.first);
				TRACE("global var '%s' removed", var1.first.c_str());
			}
		}
		for (auto var2 : vars2) {
			if (vars1.contains(var2.first)) {
				int size1 = vars1[var2.first];
				if (size1 != var2.second) {
					globalVars.changed.insert(var2.first + "/" + std::to_string(var2.second));
					TRACE("global var '%s' changed", var2.first.c_str());
				}
			} else {
				globalVars.added.insert(var2.first + "/" + std::to_string(var2.second));
				TRACE("global var '%s' added", var2.first.c_str());
			}
		}
		//scripts
		std::unordered_map<std::string, UScript*> scripts1;
		std::unordered_map<std::string, UScript*> scripts2;
		for (auto& script : file1->scriptsSection.items) {
			if (script.scriptID > 0) {
				scripts1[script.name] = &script;
			}
		}
		for (auto& script : file2->scriptsSection.items) {
			if (script.scriptID > 0) {
				scripts2[script.name] = &script;
			}
		}
		for (auto e : scripts1) {
			if (!scripts2.contains(e.first)) {
				scripts.removed.insert(e.first);
				TRACE("script '%s' removed", e.first.c_str());
				if (files2.contains(e.second->sourceFilename)) {
					if (!sources.changed.contains(e.second->sourceFilename)) {
						sources.changed.insert(e.second->sourceFilename);
						TRACE("file '%s' changed", e.second->sourceFilename.c_str());
					}
				}
			}
		}
		for (auto e : scripts2) {
			if (scripts1.contains(e.first)) {
				UScript* script1 = scripts1[e.first];
				UScript* script2 = e.second;
				TRACE("comparing scripts '%s'", e.first.c_str());
				if (*script1 != *script2) {
					scripts.changed.insert(e.first);
					TRACE("  script '%s' changed", e.first.c_str());
					if (files1.contains(e.second->sourceFilename)) {
						if (!sources.changed.contains(e.second->sourceFilename)) {
							sources.changed.insert(e.second->sourceFilename);
							TRACE("file '%s' changed", e.second->sourceFilename.c_str());
						}
					}
				} else {
					TRACE("  scripts '%s' has no changes", e.first.c_str());
				}
			} else {
				scripts.added.insert(e.first);
				TRACE("script '%s' added", e.first.c_str());
				if (files1.contains(e.second->sourceFilename)) {
					if (!sources.changed.contains(e.second->sourceFilename)) {
						sources.changed.insert(e.second->sourceFilename);
						TRACE("file '%s' changed", e.first.c_str());
					}
				}
			}
		}
		//sources
		for (auto e : files1) {
			if (!files2.contains(e)) {
				sources.removed.insert(e);
				TRACE("file '%s' removed", e.c_str());
			}
		}
		for (auto e : files2) {
			if (!files1.contains(e)) {
				sources.added.insert(e);
				TRACE("file '%s' added", e.c_str());
			}
		}
		//data
		auto data1 = file1->data.getStrings();
		auto data2 = file2->data.getStrings();
		for (auto e : data1) {
			if (!data2.contains(e)) {
				data.removed.insert(e);
				TRACE("string removed: '%s'", e.c_str());
			}
		}
		for (auto e : data2) {
			if (!data1.contains(e)) {
				data.added.insert(e);
				TRACE("string added: '%s'", e.c_str());
			}
		}
		//Autostart scripts
		std::unordered_set<std::string> autostarts1;
		std::unordered_set<std::string> autostarts2;
		for (int scriptId : file1->autoStartScripts.items) {
			int index = scriptId - 1;
			if (index >= 0 && index < (int)file1->scriptsSection.items.size()) {
				autostarts1.insert(file1->scriptsSection.items[index].name);
			}
		}
		for (int scriptId : file2->autoStartScripts.items) {
			int index = scriptId - 1;
			if (index >= 0 && index < (int)file2->scriptsSection.items.size()) {
				autostarts1.insert(file2->scriptsSection.items[index].name);
			}
		}
		for (auto e : autostarts1) {
			if (!autostarts2.contains(e)) {
				autostartScripts.removed.insert(e);
				TRACE("autostart script '%s' removed", e.c_str());
			}
		}
		for (auto e : autostarts2) {
			if (!autostarts1.contains(e)) {
				autostartScripts.added.insert(e);
				TRACE("autostart script '%s' added", e.c_str());
			}
		}
	}
};


bool UScript::isGlobalVar(int varId) const {
	return varId >= 1 && varId <= this->globalCount;
}

bool UScript::isLocalVar(int varId) const {
	return varId > this->globalCount;
}

std::string UScript::getLocalVar(int varId) const {
	if (!isLocalVar(varId)) return "";
	int index = varId - globalCount - 1;
	if (index < 0 || index >= (int)variables.size()) {
		return "";
	}
	return variables[index];
}

std::string UScript::getGlobalVar(int varId) const {
	if (!isGlobalVar(varId)) {
		return "";
	}
	return chl->globalVariables.names[varId - 1];
}

std::string UScript::getVar(int varId) const {
	if (isLocalVar(varId)) {
		return getLocalVar(varId);
	} else {
		return getGlobalVar(varId);
	}
}

int UScript::getInstructionsCount() const {
	return lastInstructionAddress - instructionAddress + 1;
}

std::list<int>::const_iterator UScript::getFirstStringInstruction() const {
	const auto& stringInstructions = this->chl->getStringInstructions();
	auto it = stringInstructions.begin();
	while (it != stringInstructions.end()) {
		const int instr = *it;
		if (instr > lastInstructionAddress) {
			TRACE("string reference at instruction %i doesn't belong to script '%s' (which ends at %i)", instr, name.c_str(), lastInstructionAddress);
			break;
		} else if (instr >= this->instructionAddress) {
			TRACE("first string reference in script '%s' is at instruction %i", name.c_str(), instr);
			return it;
		}
		it++;
	}
	TRACE("script '%s' has no string reference", name.c_str());
	return stringInstructions.end();
}

void UScript::finalize() {
	Instruction* instr = chl->instructions.pFirst + instructionAddress;
	while (instr < chl->instructions.pEnd) {
		if (instr->opcode == END) {
			break;
		}
		instr++;
	}
	lastInstructionAddress = instr - chl->instructions.pFirst;
	TRACE("script '%s' starts at %i and terminates at %i", name.c_str(), instructionAddress, lastInstructionAddress);
}

bool UScript::operator==(UScript const& other) const {
	if (this == &other) return true;
	if (this->name != other.name) return false;
	if (this->scriptType != other.scriptType) return false;
	if (this->parameterCount != other.parameterCount) return false;
	if (this->variables != other.variables) return false;
	auto& scripts1 = this->chl->scriptsSection.items;
	auto& scripts2 = other.chl->scriptsSection.items;
	auto stringInstructionIt = other.getFirstStringInstruction();
	const auto stringInstructionEnd = other.chl->getStringInstructions().end();
	int stringInstr = stringInstructionIt != stringInstructionEnd ? *stringInstructionIt : 0x7FFFFFFF;
	TRACE("first instruction to compare as string reference: %u", stringInstr);
	auto& instructions1 = this->chl->instructions;
	auto& instructions2 = other.chl->instructions;
	const int offset1 = this->instructionAddress;
	const int offset2 = other.instructionAddress;
	int srcAddr = other.instructionAddress;
	Instruction* it1 = instructions1.pFirst + offset1;
	Instruction* it2 = instructions2.pFirst + offset2;
	while (true) {
		if (it1 >= instructions1.pEnd || it2 >= instructions2.pEnd) return false;
		Instruction& instr1 = (*it1);
		Instruction& instr2 = (*it2);
		if (instr1.opcode == END || instr2.opcode == END) {
			if (instr1.opcode == instr2.opcode) break;
			TRACE("script has a different size");
			return false;
		}
		//
		if (instr1.opcode != instr2.opcode) return false;
		if (instr1.mode != instr2.mode) return false;
		if (instr1.datatype != instr2.datatype) return false;
		int opcode = instr1.opcode;
		DWORD mode = instr1.mode;
		DWORD attr = opcode_attrs[opcode];
		bool popNull = opcode == Opcodes::POP && instr1.intVal == 0;
		if ((attr & OP_ATTR_ARG) == OP_ATTR_ARG && !popNull) {
			if ((attr & OP_ATTR_IP) == OP_ATTR_IP) {
				int relDst1 = instr1.intVal - offset1;
				int relDst2 = instr2.intVal - offset2;
				if (relDst1 != relDst2) {
					TRACE("instruction %i is a jump to a different offset", srcAddr);
					return false;
				}
			} else if ((attr & OP_ATTR_SCRIPT) == OP_ATTR_SCRIPT) {
				if (instr1.intVal < 0 || instr1.intVal >= (int)scripts1.size()) return false;
				if (instr2.intVal < 0 || instr2.intVal >= (int)scripts2.size()) return false;
				UScript& target1 = scripts1[instr1.intVal];
				UScript& target2 = scripts2[instr2.intVal];
				if (target1.name != target2.name) {
					TRACE("instruction %i is a call to a different script ('%s' instead of '%s')", srcAddr, target2.name.c_str(), target1.name.c_str());
					return false;
				}
			} else if ((opcode == PUSH || opcode == POP || opcode == CAST) && (mode == 2 || instr1.datatype == DataTypes::DT_VAR)) {
				const int id1 = instr1.datatype == DataTypes::DT_VAR ? (int)instr1.floatVal : instr1.intVal;
				const int id2 = instr2.datatype == DataTypes::DT_VAR ? (int)instr2.floatVal : instr2.intVal;
				std::string name1 = this->getVar(id1);
				std::string name2 = other.getVar(id2);
				if (name1 == "") {
					ERR("invalid variable ID: %i", id1);
					return false;
				}
				if (name2 == "") {
					ERR("invalid variable ID: %i", id2);
					return false;
				}
				if (name1 != name2) {
					TRACE("instruction %i references a different variable ('%s' instead of '%s')", srcAddr, name2.c_str(), name1.c_str());
					return false;
				}
			} else if (instr1.datatype == DataTypes::DT_INT) {
				while (srcAddr > stringInstr) {
					stringInstructionIt++;
					stringInstr = stringInstructionIt != stringInstructionEnd ? *stringInstructionIt : 0x7FFFFFFF;
					TRACE("next instruction to compare as string reference: %u", stringInstr);
				}
				if (srcAddr == stringInstr) {					//String references
					TRACE("comparing instruction %u as string reference", srcAddr);
					const char* str1 = this->chl->data.getString(instr1.intVal);
					const char* str2 = other.chl->data.getString(instr2.intVal);
					if (str1 == NULL) {
						TRACE("  left operand isn't a valid string reference");
						return false;
					} else if (str2 == NULL) {
						ERR("cannot find string '%s'", str2);
						return false;
					} else {
						if (strcmp(str1, str2) != 0) {
							TRACE("  '%s' != '%s'", str1, str2);
							return false;
						} else {
							TRACE("  '%s' == '%s'", str1, str2);
						}
					}
				} else if (instr1.intVal != instr2.intVal) {	//Enums
					TRACE("instruction %i references a different constant ('%i' instead of '%i')", srcAddr, instr2.intVal, instr1.intVal);
					return false;
				}
			} else {
				Instruction* nInstr1 = it1 + 2;
				Instruction* nInstr2 = it1 + 2;
				if (nInstr1 < instructions1.pEnd && nInstr2 < instructions2.pEnd
						&& nInstr1->opcode == Opcodes::REF_PUSH && nInstr1->mode == 2
						&& nInstr2->opcode == Opcodes::REF_PUSH && nInstr2->mode == 2) {
					int id1 = (int)it1->floatVal;
					int id2 = (int)it2->floatVal;
					std::string name1 = this->getVar(id1);
					std::string name2 = other.getVar(id2);
					if (name1 == "") {
						ERR("invalid variable ID: %i", id1);
						return false;
					}
					if (name2 == "") {
						ERR("invalid variable ID: %i", id2);
						return false;
					}
					if (name1 != name2) {
						TRACE("instruction %i references a different variable ('%s' instead of '%s')", srcAddr, name2.c_str(), name1.c_str());
						return false;
					}
				} else if (instr1.intVal != instr2.intVal) {	//This works for FLOAT and BOOL too
					TRACE("instruction %i references a different value ('%f' instead of '%f')", srcAddr, instr2.floatVal, instr1.floatVal);
					return false;
				}
			}
		} else if (instr1.intVal != instr2.intVal) {		//This works for FLOAT and BOOL too
			TRACE("instruction %i references a different value ('%i' instead of '%i')", srcAddr, instr2.intVal, instr1.intVal);
			return false;
		}
		//
		srcAddr++;
		it1++;
		it2++;
	}
	return true;
}