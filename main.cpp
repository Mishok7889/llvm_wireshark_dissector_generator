//	The app generates dissector for wireshark for any struct which consist of POD
//
// Implemented features
//		Bitfield processing			-- 
//		int fields processing		-- Ok
//		string(char[]) processing   -- 
//		array(uint8_t[]) processing	-- Ok
//		enum processing				-- Ok
//		substruct processing		--

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/ASTConsumers.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <iostream>
#include <llvm/Support/CommandLine.h>
#include <regex>

using namespace clang;
using namespace clang::tooling;

std::string replaceWhitespaces(const std::string& input,
	const std::string& replacement) {
	// Use a regular expression to replace multiple whitespaces with a single one
	std::regex multipleWhitespaces("\\s+");
	std::string trimmed = std::regex_replace(input, multipleWhitespaces, " ");

	// Now replace remaining single whitespaces with the specified replacement string
	size_t start = 0;
	while ((start = trimmed.find(" ", start)) != std::string::npos) {
		trimmed.replace(start, 1, replacement);
		start += replacement.length();
	}

	return trimmed;
}

std::string toLowercase(const std::string& val,
	const std::string& spaceFiller = " ") {
	std::string res;
	res.resize(val.size());
	std::transform(val.begin(), val.end(), res.begin(),
		[](char c) { return std::tolower(c); });

	return replaceWhitespaces(res, spaceFiller);
}

std::string toUppercase(const std::string& val,
	const std::string& spaceFiller = " ") {
	std::string res;
	res.resize(val.size());
	std::transform(val.begin(), val.end(), res.begin(),
		[](char c) { return std::toupper(c); });

	return replaceWhitespaces(res, spaceFiller);
}

struct StructField {
public:
	StructField(std::string_view name, std::string_view protoName, std::string_view type, int size) : m_name(name), m_lowercaseProtoName(protoName), m_type(type), m_size(size) {}

	virtual ~StructField() {};

	virtual std::string
		getWiresharkAddItemStatement(std::string_view treeName,
			std::string_view hfIndex) const = 0;
	virtual std::optional<std::string> getMapValueWiresharkStatement() const = 0;
	virtual std::string getRegisterStatement() const = 0;
	const std::string& getType() const
	{
		return m_type;
	}

public:
	std::string m_type;
	std::string m_name;
	std::string m_lowercaseProtoName;
	int m_size;
};

struct StructInfo {
	std::string name;
	std::vector<std::unique_ptr<StructField>> fields;
	std::vector<std::string> fileDeclarations;
	std::vector<std::string> subTreeItems;
	std::map<std::string, std::string> subStructsDefinition; //Map name of struct, definition

	std::string getLowercaseName() const { return toLowercase(name); }
};

bool typeIsStaticArray(std::string_view type)
{
	return type.find('[') != std::string::npos && type.find(']') != std::string::npos;
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

static const std::map<std::string, std::string> typesMap{
	{"uint8_t", "FT_UINT8"},   {"uint16_t", "FT_UINT16"},
	{"uint32_t", "FT_UINT32"}, {"uint64_t", "FT_UINT64"},

	{"int8_t", "FT_INT8"},     {"int16_t", "FT_INT16"},
	{"int32_t", "FT_INT32"},   {"int", "FT_INT32"},
	{"int64_t", "FT_INT64"},   {"long", "FT_INT64"},

	{"char", "FT_CHAR"},       {"bool", "FT_BOOLEAN"},
};

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
	const auto fieldName =
		toUppercase(lowercaseProtoName) + ' ' + toLowercase(field.m_name);
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

struct SubstructField final : public StructField {
	SubstructField(std::string_view name, StructInfo&& sInfo, std::string_view type, int size)
		: StructField(name, sInfo.name, type, size), m_structInfo(std::move(sInfo)) {

	}

	std::string getRegisterStatement() const override
	{
		std::string res;

		for (const auto& el : m_structInfo.fields)
		{
			res += el->getRegisterStatement();
		}

		return res;
	}

	std::string getWiresharkAddItemStatement(std::string_view treeName, std::string_view hfIndex) const override {
		std::string res;

		res += std::format(R"(dissect_{}(tvb, pinfo, {}, offset); )", toLowercase(m_type), treeName);
		res += "\n";

		res += std::format("offset += {};", m_size);

		return res;
	}

	std::optional<std::string> getMapValueWiresharkStatement() const override {
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
private:
	StructInfo m_structInfo;
};

struct ConstantArrayField final : public StructField {
	ConstantArrayField(std::string_view name, std::string_view protoName, std::string_view type, int sizeOfSingleElement, int numberOfElements)
		: StructField(name, protoName, type, sizeOfSingleElement* numberOfElements), m_sizeOfSingleElement(sizeOfSingleElement), m_numberOfElements(numberOfElements) {

	}

	std::string getRegisterStatement() const override
	{
		return mapToRegister(*this, m_lowercaseProtoName);
	}

	std::string getWiresharkAddItemStatement(std::string_view treeName,
		std::string_view hfIndex) const override {
		std::string res;
		res += std::format(R"(wmem_allocator_t *allocator = wmem_packet_scope();)");
		res += "\n";
		res += std::format(R"(auto packet_str = tvb_bytes_to_str_punct(allocator, tvb, offset, {}, ' ');)", m_size);
		res += "\n";
		res += std::format(R"(proto_tree_add_bytes_format({}, {}, tvb, offset, {}, NULL, "Array: %s", packet_str);)",
			treeName, hfIndex, m_size, m_numberOfElements);
		res += "\n";

		res += std::format(R"(offset += {};)", m_size);
		res += "\n";

		return res;
	};

	std::optional<std::string> getMapValueWiresharkStatement() const override {
		return std::nullopt;
	};

private:
	const int m_sizeOfSingleElement;
	const int m_numberOfElements;
};

struct EnumField final : public StructField {
	// Using designated initializers in the constructor
	EnumField(std::string_view type, std::string_view protoName, std::string_view name,
		int size, std::map<std::string, long>& enumFields)
		: StructField(name, protoName, type, size), enumFields(enumFields) {}

	std::string getRegisterStatement() const override
	{
		return mapToRegister(*this, m_lowercaseProtoName);
	}

	std::string getValueStringMapping() const {
		std::ostringstream code;

		for (const auto& pair : enumFields) {
			code << "{static_cast<guint32>(" << pair.second << "), \"" << pair.first
				<< "\"},\n";
		}

		return code.str();
	}

	std::optional<std::string>
		getMapValueWiresharkStatement() const override {
		const auto listName = m_name + "Names";
		return "static value_string " + listName + "[]\n{\n" +
			getValueStringMapping() + "};\n\n";
	}

	std::string getWiresharkAddItemStatement(
		std::string_view treeName,
		std::string_view hfIndex) const override {
		std::ostringstream code;

		const auto listName = m_name + "Names";

		code << "proto_tree_add_item(" << treeName << "," << hfIndex
			<< ", tvb, offset," << m_size << ", ENC_BIG_ENDIAN);";
		code << "\noffset += " << m_size << ";\n";

		return code.str();
	}

	std::map<std::string, long> enumFields;
};

struct StructTrivialField : public StructField {
	// Using designated initializers in the constructor
	StructTrivialField(std::string_view type, std::string_view protoName, std::string_view name, int size)
		: StructField(name, protoName, type, size) {}

	std::string getRegisterStatement() const override
	{
		return mapToRegister(*this, m_lowercaseProtoName);
	}

	virtual std::string getWiresharkAddItemStatement(
		std::string_view treeName,
		std::string_view hfIndex) const override final {
		std::ostringstream code;
		/*if (getType() == "char") {
		  code << "proto_tree_add_string_format(" << treeName << "," << hfIndex
			   << ", tvb, offset, " << size
			   << ", \"\", \" Character : %c \", tvb_get_guint8(tvb, offset));";
		} else {*/
		code << "proto_tree_add_item(" << treeName << "," << hfIndex
			<< ", tvb, offset," << m_size << ", ENC_BIG_ENDIAN);";
		//}

		code << "\noffset += " << m_size << ";\n";

		return code.str();
	}

	std::optional<std::string>
		getMapValueWiresharkStatement() const override final {
		return std::nullopt;
	}
};

std::string generateIncludes(const StructInfo& sInfo) {
	std::stringstream os;

	os << "#include \"config.h\"\n"
		"#include <epan/packet.h>\n"
		"#include <utility>\n"
		"#include <cassert>\n"
		"#include <iterator>\n"
		"#include <algorithm>\n"
		"#include <sstream>\n"
		"#include <iomanip>\n"
		"#include <string>\n\n";

	os << "std::string tvb_to_hex_string(tvbuff_t * tvb, int offset, int "
		"length)\n"
		"{\n"
		" std::stringstream ss;\n"
		" for (int i = 0; i < length; ++i) {\n"
		"   guint8 byte = tvb_get_guint8(tvb, offset + i);\n"
		"   ss << std::hex << std::setw(2) << std::setfill('0')\n"
		"      << static_cast<int>(byte);\n"
		" }\n"
		" return ss.str();\n"
		"}\n\n";

	os << "static void preActions(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* "
		"data _U_){\n\n}";

	return os.str();
}

// The file declarations field can be changed by the function
std::string generateProtoRegister(StructInfo& sInfo) {
	std::ostringstream os;

	const auto lowercaseProtoName = sInfo.getLowercaseName();

	os << "extern \"C\" void proto_register_" << lowercaseProtoName
		<< "(void)\n{";

	os << "proto_" << lowercaseProtoName << " = proto_register_protocol(\""
		<< sInfo.name << "\",\"" << sInfo.name << "\",\"" << lowercaseProtoName
		<< "\");\n";

	os << "static hf_register_info hf[]{\n";

	for (const auto& field : sInfo.fields) {
		os << field->getRegisterStatement();
	}

	os << "};\n";

	os << "static int* ett[] {\n&";

	std::copy(sInfo.subTreeItems.begin(), sInfo.subTreeItems.end() - 1,
		std::ostream_iterator<std::string>(os, "\n&,"));

	os << sInfo.subTreeItems.back() << "\n};\n";

	os << "proto_register_field_array(proto_" << lowercaseProtoName
		<< ", hf, array_length(hf));\n";
	os << "proto_register_subtree_array(ett, array_length(ett));\n";

	os << "}";

	return os.str();
}

std::string generateRegisterHandoff(const StructInfo& sInfo) {
	const auto lowercaseName = sInfo.getLowercaseName();

	std::ostringstream os;

	os << "extern \"C\" void proto_reg_handoff_" << lowercaseName << "(void){\n";

	os << "static dissector_handle_t " << lowercaseName
		<< "_handle = create_dissector_handle(dissect_" << lowercaseName
		<< ", proto_" << lowercaseName << ");\n";

	os << "dissector_add_uint(\"udp.port\", 9999, " << lowercaseName
		<< "_handle);\n";

	os << "}";

	return os.str();
}

std::string generateDissectorBody(StructInfo& structInfo) {
	std::string res;

	const auto lowercaseName = structInfo.getLowercaseName();

	for (const auto& field : structInfo.fields) {
		res += "{\n";
		res += field->getWiresharkAddItemStatement(
			lowercaseName + "_tree", "hf_" + lowercaseName + "_" + toLowercase(field->m_name));
		res += "}\n";
		res += "\n\n";

		const auto fieldNameId =
			"hf_" + structInfo.getLowercaseName() + '_' + toLowercase(field->m_name, "_");
		structInfo.fileDeclarations.push_back("static int " + fieldNameId + ";");
	}

	res += "return tvb_captured_length(tvb);";

	return res;
}

std::string generateMainDissector(StructInfo& structInfo)
{
	std::string res;

	const auto lowercaseName = structInfo.getLowercaseName();

	structInfo.fileDeclarations.push_back("static int proto_" + structInfo.getLowercaseName() + ";");
	structInfo.subTreeItems.push_back("ett_" + lowercaseName);
	structInfo.fileDeclarations.push_back("static int ett_" + lowercaseName + ";");

	res += +"static int dissect_" + structInfo.getLowercaseName()
		+ "(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* "
		"data _U_){ \n";

	res += "preActions(tvb, pinfo, tree, data);\n\n";
	res += "int offset = 0;\n\n";

	res += "col_set_str(pinfo->cinfo, COL_PROTOCOL, \"" + structInfo.name
		+ "\" );\n";
	res += "col_clear(pinfo->cinfo, COL_INFO);\n\n";

	res += "proto_item *subtree = proto_tree_add_item(tree, proto_" + lowercaseName + ", tvb, 0, -1, ENC_NA);\n";

	res += "proto_tree *" + lowercaseName
		+ "_tree = proto_item_add_subtree(subtree, ett_" + lowercaseName
		+ ");\n\n";

	res += generateDissectorBody(structInfo);

	res += " }\n";

	return res;
}

std::string generateSubDissector(StructInfo& structInfo)
{
	std::string res;

	const auto lowercaseName = structInfo.getLowercaseName();


	const auto hfIndex = "hf_" + toLowercase(structInfo.name) + "_item";
	structInfo.fileDeclarations.push_back("static int proto_" + structInfo.getLowercaseName() + ";");
	structInfo.fileDeclarations.push_back("static int " + hfIndex + ";");

	res += +"static int dissect_" + structInfo.getLowercaseName()
		+ "(tvbuff_t* tvb, packet_info* pinfo, proto_tree* subtree, int offset){ \n";

	res += "proto_tree *" + lowercaseName + "_tree = proto_tree_add_subtree(subtree, tvb, offset, -1, " + hfIndex + ", 0, \"\"); \n\n";

	res += generateDissectorBody(structInfo);

	res += " }\n";

	return res;
}

std::string GeneratedParserString;

std::string generateFileDeclarations(StructInfo& structInfo) {
	std::string res;

	for (const auto& el : structInfo.fileDeclarations) {
		res += el + '\n';
	}

	res += "\n\n";

	for (auto rit = structInfo.subStructsDefinition.rbegin(); rit != structInfo.subStructsDefinition.rend(); ++rit) {
		res += rit->second + '\n';
	}

	for (const auto& el : structInfo.fields) {
		if (const auto val = el->getMapValueWiresharkStatement())
		{
			res += *val;
		}
	}

	return res;
}

void processStruct(const RecordDecl* declaration, const ASTContext& context, StructInfo& structInfo, StructInfo& mainStruct) {
	for (auto* field : declaration->fields()) {
		const auto type = field->getType();
		const auto typeStr = field->getType().getAsString();
		const auto name = field->getName().str();
		const auto size = context.getTypeSize(type) / 8;

		if (const RecordType* RT = field->getType()->getAs<RecordType>()) {
			if (RT->getDecl()->isThisDeclarationADefinition()) {
				// Process Struct

				const auto record = RT->getDecl();
				StructInfo subInfo{ .name = typeStr };

				processStruct(record, context, subInfo, structInfo);

				auto& defMap = structInfo.subStructsDefinition;
				if (defMap.find(typeStr) == defMap.end())
				{
					mainStruct.subStructsDefinition[typeStr] = generateSubDissector(subInfo);
				}
				mainStruct.fileDeclarations.insert(mainStruct.fileDeclarations.end(), subInfo.fileDeclarations.begin(), subInfo.fileDeclarations.end());
				structInfo.fields.push_back(std::make_unique<SubstructField>(name, std::move(subInfo), typeStr, size));
			}
		}
		else if (type->isArrayType())
		{
			if (const clang::ConstantArrayType* arrayType = context.getAsConstantArrayType(type)) {
				const auto elementSize = context.getTypeSize(arrayType->getElementType()) / 8;
				const auto numberOfElements = arrayType->getSize().getZExtValue();

				structInfo.fields.push_back(std::make_unique<ConstantArrayField>(name, structInfo.name, typeStr, elementSize, numberOfElements));
			}
		}
		else if (type->isEnumeralType()) // Process enum
		{
			std::map<std::string, long> enumFields;

			const auto enumDecl = type->getAs<clang::EnumType>()->getDecl();
			if (enumDecl->isCompleteDefinition()) {
				for (auto it = enumDecl->enumerator_begin();
					it != enumDecl->enumerator_end(); ++it) {
					clang::EnumConstantDecl* enumConst = *it;
					std::string name = enumConst->getNameAsString();
					long value =
						static_cast<long>(enumConst->getInitVal().getSExtValue());

					// Add to map
					enumFields[name] = value;
				}
			}

			structInfo.fields.push_back(std::make_unique<EnumField>(
				//TODO: get underlying type, remove hardcoded one
				"uint8_t", structInfo.name, name, size, enumFields));
		}
		else {
			// Trivial type

			structInfo.fields.push_back(std::make_unique<StructTrivialField>(
				typeStr, structInfo.name, name, size));
		}
	}
}

class StructVisitor : public RecursiveASTVisitor<StructVisitor> {
public:
	explicit StructVisitor(ASTContext* context,
		const std::string& targetStructName)
		: context(context), targetStructName(targetStructName) {}

	bool VisitRecordDecl(RecordDecl* declaration) {
		if (declaration->isThisDeclarationADefinition() &&
			declaration->getNameAsString() == targetStructName) {
			// printStruct(declaration, 0);
			StructInfo structInfo{ .name = targetStructName };

			processStruct(declaration, *context, structInfo, structInfo);

			const auto includes = generateIncludes(structInfo);
			const auto dissectorFunction = generateMainDissector(structInfo);
			const auto protoRegister = generateProtoRegister(structInfo);
			const auto handoff = generateRegisterHandoff(structInfo);
			const auto fileDeclarations = generateFileDeclarations(structInfo);

			GeneratedParserString = "";
			GeneratedParserString += includes + "\n\n";
			GeneratedParserString += fileDeclarations + "\n\n";
			GeneratedParserString += dissectorFunction + "\n\n";
			GeneratedParserString += protoRegister + "\n\n";
			GeneratedParserString += handoff + "\n\n";
		}
		return true; // Continue visiting subsequent AST nodes
	}

	void printStruct(RecordDecl* declaration, int indentLevel) {
		std::string indent(indentLevel * 2, ' '); // Create indentation
		std::cout << indent << "Structure Name: " << declaration->getName().str()
			<< "\n";

		for (auto* field : declaration->fields()) {
			std::cout << indent << "  Field Name: " << field->getName().str();
			std::cout << ", Field Type: " << field->getType().getAsString();

			if (field->isBitField()) {
				std::cout << ", Bitfield Width: " << field->getBitWidthValue(*context)
					<< " bits";
			}

			// If the field is itself a struct, recurse into it
			if (const RecordType* RT = field->getType()->getAs<RecordType>()) {
				if (RT->getDecl()->isThisDeclarationADefinition()) {
					std::cout << "\n" << indent << "  Nested Struct:\n";
					printStruct(RT->getDecl(), indentLevel + 2);
				}
			}

			std::cout << "\n";
		}
	}

private:
	ASTContext* context;
	std::string targetStructName;
};

class StructConsumer : public ASTConsumer {
public:
	StructConsumer(ASTContext* context, const std::string& targetStructName)
		: visitor(context, targetStructName) {}

	void HandleTranslationUnit(ASTContext& Context) override {
		visitor.TraverseDecl(Context.getTranslationUnitDecl());
	}

private:
	StructVisitor visitor;
};

class StructAction : public ASTFrontendAction {
public:
	StructAction(const std::string& structName = "TrivialA")
		: structName(structName) {}

	std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance& CI,
		StringRef file) override {
		return std::make_unique<StructConsumer>(&CI.getASTContext(), structName);
	}

private:
	std::string structName;
};

int main(int argc, const char** argv) {

	const char* Args[] = {
		"dummy",
		"./test_struct/file.cpp", // File path
		"--",
		"-std=c++17",
	};

	int Argc = sizeof(Args) / sizeof(char*);
	llvm::cl::OptionCategory MyToolCategory("My Tool Options");
	auto OptionsParser = CommonOptionsParser::create(Argc, Args, MyToolCategory);

	if (!OptionsParser) {
		llvm::errs() << "Error parsing options: " << OptionsParser.takeError()
			<< "\n";
		return 1;
	}

	ClangTool Tool(OptionsParser->getCompilations(),
		OptionsParser->getSourcePathList());

	auto res = Tool.run(newFrontendActionFactory<StructAction>().get());

	if (!res) {
		std::cout << "Result parser: \n" << GeneratedParserString;
	}

	return res;
}