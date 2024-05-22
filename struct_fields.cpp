#include "struct_fields.h"

#include <format>
#include <string>

std::string SubstructField::getRegisterStatement() const
{
	std::string res;

	for (const auto& el : m_structInfo.fields)
	{
		res += el->getRegisterStatement();
	}

	return res;
}

std::string SubstructField::getWiresharkAddItemStatement(std::string_view treeName, std::string_view hfIndex) const {
	std::string res;

	res += std::format(R"(dissect_{}(tvb, pinfo, {}, offset); )", toLowercase(m_type), treeName);
	res += "\n";

	res += std::format("offset += {};", m_size);

	return res;
}

std::optional<std::string> SubstructField::getMapValueWiresharkStatement() const {
	std::string res;

	for (const auto& el : m_structInfo.fields)
	{
		if (const auto val = el->getMapValueWiresharkStatement())
		{
			res += *val + '\n';
		}
	}

	return res;
}

std::string ConstantArrayField::getRegisterStatement() const
{
	return mapToRegister(*this, m_lowercaseProtoName);
}

std::string ConstantArrayField::getWiresharkAddItemStatement(std::string_view treeName,
	std::string_view hfIndex) const {
	std::string res;
	res += std::format(R"(wmem_allocator_t *allocator = wmem_packet_scope();)");
	res += "\n";
	res += std::format(R"(auto packet_str = tvb_bytes_to_str_punct(allocator, tvb, offset, {}, ' ');)", m_size);
	res += "\n";
	res += std::format(R"(proto_tree_add_bytes_format({}, {}, tvb, offset, {}, NULL, "{}: %s", packet_str);)",
		treeName, hfIndex, m_size, m_name);
	res += "\n";

	res += std::format(R"(offset += {};)", m_size);
	res += "\n";

	return res;
};

std::optional<std::string> ConstantArrayField::getMapValueWiresharkStatement() const {
	return std::nullopt;
};

std::string EnumField::getRegisterStatement() const
{
	return mapToRegister(*this, m_lowercaseProtoName);
}

std::string EnumField::getValueStringMapping() const {
	std::string res;

	for (const auto& pair : enumFields) {
		res += std::format("{{static_cast<guint32>({}), \"{}\"}},\n", std::to_string(pair.second), pair.first);
	}

	return res;
}

std::optional<std::string>
EnumField::getMapValueWiresharkStatement() const {
	const auto listName = m_name + "Names";
	return "static value_string " + listName + "[]\n{\n" +
		getValueStringMapping() + "};\n\n";
}

std::string EnumField::getWiresharkAddItemStatement(std::string_view treeName, std::string_view hfIndex) const {
	std::string res;

	const auto listName = m_name + "Names";

	res += std::format("proto_tree_add_item({}, {}, tvb, offset, {}, ENC_BIG_ENDIAN);", treeName, hfIndex, m_size);
	res += std::format("\noffset += {};\n", m_size);

	return res;
}

std::string StructTrivialField::getRegisterStatement() const
{
	return mapToRegister(*this, m_lowercaseProtoName);
}

std::string StructTrivialField::getWiresharkAddItemStatement(
	std::string_view treeName,
	std::string_view hfIndex) const {
	std::string res;

	res += std::format("proto_tree_add_item({}, {}, tvb, offset, {}, ENC_BIG_ENDIAN);", treeName, hfIndex, m_size);
	res += std::format("\noffset += {};\n", m_size);

	return res;
}

std::optional<std::string> StructTrivialField::getMapValueWiresharkStatement() const {
	return std::nullopt;
}