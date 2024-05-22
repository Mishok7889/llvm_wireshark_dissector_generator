//	The app generates dissector for wireshark for any struct which consist of POD
//
// Implemented features
//		Bitfield processing			-- 
//		int fields processing		-- Ok
//		string(char[]) processing   -- 
//		array(uint8_t[]) processing	-- Ok
//		enum processing				-- Ok
//		substruct processing		-- Ok

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/ASTConsumers.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <iostream>
#include <llvm/Support/CommandLine.h>
#include <regex>

#include "utils.h"
#include "struct_fields.h"

using namespace clang;
using namespace clang::tooling;

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

	res += "proto_tree *" + lowercaseName + "_tree = proto_tree_add_subtree(subtree, tvb, offset, -1, " + hfIndex + ", 0, \"" + structInfo.inCodeName + "\"); \n\n";

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
				StructInfo subInfo{ .name = typeStr, .inCodeName = name};

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