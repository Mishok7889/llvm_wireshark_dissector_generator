#include "IStruct.h"

#include <map>
#include <iostream>
#include <format>

#include "utils.h"


std::string mapTypeToWiresharkType(const StructField& field) {
	const auto type = field.getType();

	const auto it = typesMap.find(type);
	if (it != typesMap.end()) {
		return it->second;
	}

	//TODO: refactor static array check
	if (typeIsStaticArray(type))
	{
		return "FT_BYTES";
	}

	std::cerr << "Invalid type, cannot map(" << type << ")\n";
	//return "UNKNOWN_TYPE(" + type + ")";
	return "";
}

std::string mapToRegister(const StructField& field, std::string protoName)
{
	const auto lowercaseProtoName = toLowercase(protoName);

	std::string res;

	const auto fieldType = mapTypeToWiresharkType(field);
	if (fieldType.empty()) return "";

	const auto fieldNameId =
		"hf_" + lowercaseProtoName + '_' + toLowercase(field.m_name, "_");
	const auto fieldName = toLowercase(field.m_name);
	const auto fieldAbbrev =
		toLowercase(lowercaseProtoName) + "." + toLowercase(field.m_name, "_");

	const auto displayBase = mapTypeToWiresharkDisplayBase(field);

	const auto valueMappingList = field.getMapValueWiresharkStatement();
	const auto valueMapping =
		valueMappingList
		? ("VALS(" + toLowercase(field.m_name) + "Names)")
		: "NULL";

	const auto bitFlag = "0x0";
	res += std::format(R"(
{{
	&{}, {{ "{}", "{}",
	{}, {},
	{}, {},
	NULL, HFILL }}
}},
)", fieldNameId, fieldName, fieldAbbrev, fieldType, displayBase, valueMapping, bitFlag);

	return res;
}

std::string mapTypeToWiresharkDisplayBase(const StructField& field) {
	if (field.getType() == "int8_t" || field.getType() == "int16_t" ||
		field.getType() == "int32_t" || field.getType() == "int64_t" ||
		field.getType() == "int" || field.getType() == "long") {
		return "BASE_DEC";
	}

	if (typeIsStaticArray(field.getType()))
	{
		return "BASE_NONE";
	}

	return "BASE_HEX";
}