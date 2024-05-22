#include "utils.h"

#include <regex>

std::string replaceWhitespaces(const std::string& input, const std::string& replacement) {
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

std::string toLowercase(const std::string& val, const std::string& spaceFiller) {
	std::string res;
	res.resize(val.size());
	std::transform(val.begin(), val.end(), res.begin(),
		[](char c) { return std::tolower(c); });

	return replaceWhitespaces(res, spaceFiller);
}

std::string toUppercase(const std::string& val, const std::string& spaceFiller) {
	std::string res;
	res.resize(val.size());
	std::transform(val.begin(), val.end(), res.begin(),
		[](char c) { return std::toupper(c); });

	return replaceWhitespaces(res, spaceFiller);
}