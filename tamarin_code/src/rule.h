#ifndef NEW_RULE
#define NEW_RULE

#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <memory>

std::vector<std::string> SplitOperationString(const std::string &curr_str, int start, int &end);

std::vector<std::vector<std::string>> SplitString(const std::string &curr_str);

// Rule
struct Rule {
    std::string name;
    int ruleNumber;
    std::string agent;
    std::set<std::string> ruleCharSet;
    std::string ruleCharString;
    std::vector<std::string> leftPart;
    std::vector<std::string> rightPart;
    std::string actionPart;
    //std::map<std::string, std::string> letPart;
    std::vector<std::string> letPart;

    void SetToString();
    void WriteLetPart(std::ofstream &tamatinOut);
    void WriteRule(std::ofstream &tamatinOut);
};

#endif