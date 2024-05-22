#pragma once
#include <optional>
#include <vector>
#include <memory>
#include <map>

#include "utils.h"

inline const std::map<std::string, std::string> typesMap{
	{"uint8_t", "FT_UINT8"},   {"uint16_t", "FT_UINT16"},
	{"uint32_t", "FT_UINT32"}, {"uint64_t", "FT_UINT64"},

	{"int8_t", "FT_INT8"},     {"int16_t", "FT_INT16"},
	{"int32_t", "FT_INT32"},   {"int", "FT_INT32"},
	{"int64_t", "FT_INT64"},   {"long", "FT_INT64"},

	{"char", "FT_CHAR"},       {"bool", "FT_BOOLEAN"},
	{"_Bool", "FT_BOOLEAN"},
};

struct StructField {
public:
	StructField(std::string_view name, std::string_view protoName, std::string_view type, int size) : m_name(name), m_lowercaseProtoName(protoName), m_type(type), m_size(size) {}

	virtual ~StructField() {};

	virtual std::string
		getWiresharkAddItemStatement(std::string_view treeName,
			std::string_view hfIndex) const = 0;
	virtual std::optional<std::string> getMapValueWiresharkStatement() const = 0;
	virtual std::string getRegisterStatement() const = 0;
	inline const std::string& getType() const { return m_type; }

public:
	std::string m_type;
	std::string m_name;
	std::string m_lowercaseProtoName;
	int m_size;
};

struct StructInfo {
	std::string name;
	std::string inCodeName;
	std::vector<std::unique_ptr<StructField>> fields;
	std::vector<std::string> fileDeclarations;
	std::vector<std::string> subTreeItems;
	std::map<std::string, std::string> subStructsDefinition; //Map name of struct, definition

	std::string getLowercaseName() const { return toLowercase(name); }
};

inline bool typeIsStaticArray(std::string_view type)
{
	return type.find('[') != std::string::npos && type.find(']') != std::string::npos;
}

std::string mapTypeToWiresharkType(const StructField& field);

std::string mapToRegister(const StructField& field, std::string protoName);

std::string mapTypeToWiresharkDisplayBase(const StructField& field);