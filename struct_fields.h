#pragma once
#include <map>

#include "IStruct.h"

struct SubstructField final : public StructField {
	SubstructField(std::string_view name, StructInfo&& sInfo, std::string_view type, int size)
		: StructField(name, sInfo.name, type, size), m_structInfo(std::move(sInfo)) {

	}

	std::string getRegisterStatement() const override;
	std::string getWiresharkAddItemStatement(std::string_view treeName, std::string_view hfIndex) const override;
	std::optional<std::string> getMapValueWiresharkStatement() const override;
private:
	StructInfo m_structInfo;
};

struct ConstantArrayField final : public StructField {
	ConstantArrayField(std::string_view name, std::string_view protoName, std::string_view type, int sizeOfSingleElement, int numberOfElements)
		: StructField(name, protoName, type, sizeOfSingleElement* numberOfElements), m_sizeOfSingleElement(sizeOfSingleElement), m_numberOfElements(numberOfElements) {

	}

	std::string getRegisterStatement() const override;
	std::string getWiresharkAddItemStatement(std::string_view treeName, std::string_view hfIndex) const override;
	std::optional<std::string> getMapValueWiresharkStatement() const override;

private:
	const int m_sizeOfSingleElement;
	const int m_numberOfElements;
};

struct EnumField final : public StructField {
	// Using designated initializers in the constructor
	EnumField(std::string_view type, std::string_view protoName, std::string_view name,
		int size, std::map<std::string, long>& enumFields)
		: StructField(name, protoName, type, size), enumFields(enumFields) {}

	std::string getValueStringMapping() const;

	std::string getRegisterStatement() const override;
	std::string getWiresharkAddItemStatement(std::string_view treeName, std::string_view hfIndex) const override;
	std::optional<std::string> getMapValueWiresharkStatement() const override;

	std::map<std::string, long> enumFields;
};

struct StructTrivialField final : public StructField {
	// Using designated initializers in the constructor
	StructTrivialField(std::string_view type, std::string_view protoName, std::string_view name, int size)
		: StructField(name, protoName, type, size) {}

	std::string getRegisterStatement() const override;
	std::string getWiresharkAddItemStatement(std::string_view treeName, std::string_view hfIndex) const override;
	std::optional<std::string> getMapValueWiresharkStatement() const override;
};