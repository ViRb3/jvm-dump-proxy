#ifndef VERSION_PARSER_H
#define VERSION_PARSER_H

#include <string>
#include <vector>
#include <winsock.h> // link with "ws2_32"

using namespace std;

//
// Simple Java Class Parser
// Supported: Up to Java 14
//
// Reference:
// https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html#jvms-4.4
//

// Disable structure alignment as we will cast bytes directly into them, and we want them to be accurate.
#pragma pack(push, 1)

// Java values are big endian, so we need to create wrappers to reverse them.
#pragma region Big endian wrappers

class be_uint16_t {
public:
    be_uint16_t() : be_val_(0) {}

    be_uint16_t(const uint16_t &val) : be_val_(htons(val)) {}

    operator uint16_t() const { return ntohs(be_val_); }

private:
    uint16_t be_val_;
};

class be_uint32_t {
public:
    be_uint32_t() : be_val_(0) {}

    be_uint32_t(const uint32_t &val) : be_val_(htonl(val)) {}

    operator uint32_t() const { return ntohl(be_val_); }

private:
    uint32_t be_val_;
};

#pragma endregion

#pragma region Java structs

typedef be_uint32_t u4;
typedef be_uint16_t u2;
typedef unsigned char u1;

struct CONSTANT_Class_info {
    u1 tag;
    u2 name_index;
};

struct CONSTANT_Utf8_info {
    u1 tag;
    u2 length;
    u1 bytes[];
};

struct ClassHeader {
    u4 magic;
    u2 minor_version;
    u2 major_version;
    u2 constant_pool_count;
};

struct ClassMiddle {
    u2 access_flags;
    u2 this_class;
    u2 super_class;
};

enum Constant_pool {
    CONSTANT_Class = 7,
    CONSTANT_Fieldref = 9,
    CONSTANT_Methodref = 10,
    CONSTANT_InterfaceMethodref = 11,
    CONSTANT_String = 8,
    CONSTANT_Integer = 3,
    CONSTANT_Float = 4,
    CONSTANT_Long = 5,
    CONSTANT_Double = 6,
    CONSTANT_NameAndType = 12,
    CONSTANT_Utf8 = 1,
    CONSTANT_MethodHandle = 15,
    CONSTANT_MethodType = 16,
    CONSTANT_Dynamic = 17,
    CONSTANT_InvokeDynamic = 18,
    CONSTANT_Module = 19,
    CONSTANT_Package = 20,
};

#pragma endregion

#pragma pack(pop)

const u4 javaMagic = *(u4 *) ("\xCA\xFE\xBA\xBE");
const int classHeaderSize = sizeof(ClassHeader);

// Advances the pointer into a Java class buffer to the next constant structure.
bool nextConstant(int &i, const char *&pc, std::vector<const char *> &constant_pool) {
    constant_pool.push_back(pc);
    u1 tag = *(u1 *) pc;
    switch (tag) {
        case CONSTANT_Class:
        case CONSTANT_String:
        case CONSTANT_MethodType:
        case CONSTANT_Module:
        case CONSTANT_Package:
            pc += 3;
            break;
        case CONSTANT_Fieldref:
        case CONSTANT_Methodref:
        case CONSTANT_InterfaceMethodref:
        case CONSTANT_NameAndType:
        case CONSTANT_Dynamic:
        case CONSTANT_InvokeDynamic:
        case CONSTANT_Integer:
        case CONSTANT_Float:
            pc += 5;
            break;
        case CONSTANT_Long:
        case CONSTANT_Double:
            // All 8-byte constants take up two entries in the constant_pool table of the class file.
            constant_pool.push_back(nullptr);
            i++;
            pc += 9;
            break;
        case CONSTANT_Utf8: {
            pc += 3 + *(u2 *) (pc + 1);
            break;
        }
        case CONSTANT_MethodHandle:
            pc += 4;
            break;
        default:
            return false;
    }
    return true;
}

// Returns the class name parsed from the class bytes.
string GetJavaClassName(const char *classBuf) {
    auto header = (ClassHeader *) classBuf;
    if (header->magic != javaMagic) {
        return string("M_ERROR");
    }

    const char *pc = classBuf + classHeaderSize;
    std::vector<const char *> constant_pool(header->constant_pool_count);
    constant_pool.resize(0);

    for (int i = 0; i < header->constant_pool_count - 1; i++) {
        if (!nextConstant(i, pc, constant_pool)) {
            return string("F_ERROR");
        }
    }

    auto middle = (ClassMiddle *) pc;
    auto constClass = (CONSTANT_Class_info *) constant_pool.at(middle->this_class - 1);
    auto constUtf8 = (CONSTANT_Utf8_info *) constant_pool.at(constClass->name_index - 1);

    auto result = string(constUtf8->length + 1, '\x00');
    memcpy(result.data(), constUtf8->bytes, constUtf8->length);
    return result;
}

#endif //VERSION_PARSER_H
