//
// Created by dkulpa on 11.10.2023.
//

#include "SuperString.h"

StringList split(const std::string &s, char d){
    StringList parts;
    size_t prevPos=0;
    size_t pos = 0;

    while (pos!=s.length() and (pos = s.find(d, prevPos)) != std::string::npos) {
        std::string part= s.substr(prevPos, pos-prevPos);
        prevPos= pos+1;
        parts.emplace_back(part);
    }

    if(pos!=s.length()){
        std::string part= s.substr(prevPos);
        parts.emplace_back(part);
    }

    return parts;
}

StringList splitCsvRespectingQuotes(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool inQuotes = false;
    bool startedWithQuote = false;

    const size_t n = s.size();
    for (size_t i = 0; i < n; ++i) {
        char ch = s[i];

        if (inQuotes) {
            if (ch == '"') {
                bool nextIsSepOrEnd = (i + 1 == n) || (s[i + 1] == ',');
                if (nextIsSepOrEnd) {
                    inQuotes = false;
                    continue;
                } else {
                    cur.push_back('"');
                }
            } else {
                cur.push_back(ch);
            }
        } else {
            if (ch == ',') {
                out.push_back(cur);
                cur.clear();
                startedWithQuote = false;
            } else if (ch == '"' && cur.empty()) {
                inQuotes = true;
                startedWithQuote = true;
            } else {
                cur.push_back(ch);
            }
        }
    }

    if (inQuotes && startedWithQuote) {
        cur.insert(cur.begin(), '"');
    }
    out.push_back(cur);
    return out;
}

void removeLeading(std::string &s, const std::string &l){
    if(s.length()>0) {
        bool found = true;
        size_t end = 0;

        while (found and end < s.length()) {
            found = false;
            for (auto c: l) {
                if (s[end] == c) {
                    found = true;
                    break;
                }
            }
            end++;
        }

        if(end>1){
            std::string a = s.substr(end - 1);
            s = a;
        }
    }
}

void removeLeading(std::string &s, char c){
    if(s.length()>0) {
        size_t end = 0;

        while ((s[end]==c) and end < s.length()) {
            end++;
        }

        if(end>0) {
            std::string a = s.substr(end);
            s = a;
        }
    }
}

void removeTrailing(std::string &s, const std::string &l){
    if(s.length()>0) {
        bool found = true;
        size_t end = s.length() - 1;

        while (found && end > 0) {
            found = false;
            for (auto c: l) {
                if (s[end] == c) {
                    found = true;
                    break;
                }
            }
            end--;
        }

        if(end<(s.length()-2)) {
            std::string a = s.substr(0, end + 2);
            s = a;
        }
    }
}

void removeTrailing(std::string &s, char c){
    if(s.length()>0) {
        size_t end = s.length() - 1;

        while ((s[end]==c) and end > 0) {
            end--;
        }

        if(end<(s.length()-1)) {
            std::string a = s.substr(0, end + 1);
            s = a;
        }
    }
}