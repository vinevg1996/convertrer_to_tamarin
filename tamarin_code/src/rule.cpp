#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include "rule.h"

// Help functions
std::vector<std::string> SplitOperationString(const std::string &curr_str, int start, int &end) {
    int i = start + 1;
    std::vector<std::string> operation_str;
    std::string word;
    word.push_back('[');
    operation_str.push_back(word);
    word.clear();
    while(curr_str[i] != ']') {
        if (curr_str[i] == ',') {
            operation_str.push_back(word);
            //std::cout << "word: " << word << std::endl;
            word.clear();
        } else {
            word.push_back(curr_str[i]);
        }
        ++i;
    }
    operation_str.push_back(word);
    //std::cout << "word: " << word << std::endl;
    word.clear();
    word.push_back(']');
    operation_str.push_back(word);
    end = i;
    return operation_str;
}

std::vector<std::vector<std::string>> SplitString(const std::string &curr_str) {
    std::vector<std::vector<std::string>> currCommand;
    std::vector<std::string> command_str;
    std::string word;
    if (curr_str.size() < 1) {
        return currCommand;
    }
    for (int i = 1; i < curr_str.size() - 1; ) {
        if (curr_str[i] == '[') {
            std::vector<std::string> operation_str;
            int end;
            operation_str = SplitOperationString(curr_str, i, end);
            for (const auto &elem: operation_str) {
                command_str.push_back(elem);
            }
            i = end;
            //std::cout << "i = " << curr_str[i] << std::endl;
        } else if (curr_str[i] == ' ') {
            command_str.push_back(word);
            //std::cout << "word: " << word << std::endl;
            word.clear();
        } else if (curr_str[i] == ',') {
            command_str.push_back(word);
            //std::cout << "word: " << word << std::endl;
            currCommand.push_back(command_str);
            command_str.clear();
            word.clear();
        } else {
            word.push_back(curr_str[i]);
        }
        ++i;
    }
    command_str.push_back(word);
    currCommand.push_back(command_str);
    return currCommand;
}

// Rule
void Rule::SetToString() {
    if (agent == "TTP") {
        this->ruleCharString = "TTP_Step_" + std::to_string(ruleNumber) + "(";
    } else if (agent == "Ali") {
        this->ruleCharString = "Ali_Step_" + std::to_string(ruleNumber) + "(";
    } else if (agent == "Bob") {
        this->ruleCharString = "Bob_Step_" + std::to_string(ruleNumber) + "(";
    }
    for (const auto &elem: this->ruleCharSet) {
        this->ruleCharString += (elem + ", ");
    }
    this->ruleCharString = this->ruleCharString.substr(0, this->ruleCharString.size() - 2);
    this->ruleCharString += ")";
    return;
}

void Rule::WriteLetPart(std::ofstream &tamatinOut) {
    tamatinOut << "    let" << std::endl;
    for (const auto &it: letPart) {
        tamatinOut << "        " << it.first << " = "
        << it.second << std::endl;
    }
    tamatinOut << "    in" << std::endl;
    return;
}

void Rule::WriteRule(std::ofstream &tamatinOut) {
    tamatinOut << "rule " << name << ":" << std::endl;
    if (letPart.size() > 0) {
        WriteLetPart(tamatinOut);
    }
    tamatinOut << "    [ ";
    if (leftPart.size() > 0) {
        for (int i = 0; i < leftPart.size() - 1; ++i) {
            tamatinOut << leftPart[i] << ", ";
        }
        tamatinOut << leftPart[leftPart.size() - 1];
    }
    tamatinOut << " ]" << std::endl;
    tamatinOut << "    --[" << name + "_Fact" + "(" + actionPart + ")"
    << "]->" << std::endl;
    //tamatinOut << "    --[h(" << actionPart << ")"
    //<< "]->" << std::endl;
    tamatinOut << "    [ ";
    if (rightPart.size() > 0) {
        for (int i = 0; i < rightPart.size() - 1; ++i) {
            tamatinOut << rightPart[i] << ", ";
        }
        tamatinOut << rightPart[rightPart.size() - 1];
    }
    tamatinOut << " ]" << std::endl << std::endl;
    return;
}
