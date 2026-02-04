//
// Created by dkulpa on 11.10.2023.
//

#ifndef SUPERVISOR_SUPERSTRING_H
#define SUPERVISOR_SUPERSTRING_H


#include <vector>
#include <string>

typedef std::vector<std::string> StringList;

StringList split(const std::string &s, char d);
StringList splitCsvRespectingQuotes(const std::string& s);
void removeLeading(std::string &s, const std::string &l);
void removeLeading(std::string &s, char c);
void removeTrailing(std::string &s, const std::string &l);
void removeTrailing(std::string &s, char c);



#endif //SUPERVISOR_SUPERSTRING_H
