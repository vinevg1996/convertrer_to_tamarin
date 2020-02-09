#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include "protocol.h"

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
}

void Rule::WriteLetPart(std::ofstream &tamatinOut) {
    tamatinOut << "    let" << std::endl;
    for (const auto &it: letPart) {
        tamatinOut << "        " << it.first << " = "
        << it.second << std::endl;
    }
    tamatinOut << "    in" << std::endl;
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
    tamatinOut << "    --[" << name + "_Fact" + "('" + std::to_string(ruleNumber) + "')"
    << "]->" << std::endl;
    tamatinOut << "    [ ";
    if (rightPart.size() > 0) {
        for (int i = 0; i < rightPart.size() - 1; ++i) {
            tamatinOut << rightPart[i] << ", ";
        }
        tamatinOut << rightPart[rightPart.size() - 1];
    }
    tamatinOut << " ]" << std::endl << std::endl;
}

// Protocol
void Protocol::ReadHeader(std::ifstream &tamatinIn) {
    std::string curr_str;
    while (curr_str != "TTP events:") {
        std::getline(tamatinIn, curr_str);
    }
    std::cout << curr_str << std::endl;
}

void Protocol::WriteHeader(std::ofstream &tamatinOut) {
    tamatinOut << "theory NS_DEBUG" << std::endl;
    tamatinOut << "begin" << std::endl << std::endl;
    tamatinOut << "builtins: asymmetric-encryption" << std::endl << std::endl;
    //tamatinOut << "    asymmetric-encryption" << std::endl;
    //tamatinOut << "    symmetric-encryption" << std::endl;
    //tamatinOut << "    diffie-hellman" << std::endl << std::endl;
    tamatinOut << "functions:" << std::endl;
    tamatinOut << "    ECMult/3," << std::endl;
    tamatinOut << "    Encrypt/2," << std::endl;
    tamatinOut << "    Decrypt/2" << std::endl << std::endl;
    tamatinOut << "equations:" << std::endl;
    tamatinOut << "    Decrypt(Encrypt(mess, ECMult(vCurve, vBasePoint, key)), key) = mess"
    << std::endl << std::endl;
}

void Protocol::WriteInLetPartOfRule(Rule &rule) {
    for (const auto &elem: rule.ruleCharSet) {
        if (rule.agent == "TTP") {
            auto it = TTP_variables.find(elem);
            if ((it != TTP_variables.end()) && (it->second.size() > 0)) {
                rule.letPart[it->first] = it->second;
            }
        } else if (rule.agent == "Ali") {
            auto it = Ali_variables.find(elem);
            if ((it != Ali_variables.end()) && (it->second.size() > 0)) {
                rule.letPart[it->first] = it->second;
            }
        } else if (rule.agent == "Bob") {
            auto it = Bob_variables.find(elem);
            if ((it != Bob_variables.end()) && (it->second.size() > 0)) {
                rule.letPart[it->first] = it->second;
            }
        }
    }
}

Protocol::Protocol(const std::string &inputFile, const std::string &outputFile) {
    std::ifstream tamatinIn(inputFile);
    std::ofstream tamatinOut(outputFile);
    ReadHeader(tamatinIn);
    WriteHeader(tamatinOut);
    std::string curr_str;
    int curr_rule = 0;
    // TTP events:
    std::getline(tamatinIn, curr_str);
    while (curr_str != "Ali events:") {
        if (curr_str.size() > 1) {
            ExecuteExpression(curr_str, tamatinOut, "TTP", curr_rule);
        }
        std::getline(tamatinIn, curr_str);
    }
    curr_rule = 0;
    // Ali events:
    
    while (curr_str != "Bob events:") {
        if (curr_str.size() > 1) {
            ExecuteExpression(curr_str, tamatinOut, "Ali", curr_rule);
        }
        std::getline(tamatinIn, curr_str);
    }
    curr_rule = 0;
    
    // Bob events:
    while (std::getline(tamatinIn, curr_str)) {
        if (curr_str.size() > 1) {
            ExecuteExpression(curr_str, tamatinOut, "Bob", curr_rule);
        }
    }
    curr_rule = 0;
    
    tamatinOut << "end" << std::endl;
}

void Protocol::ProcessKey(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent, int &curr_rule) {
    Rule rule;
    keys.insert(currCommand[2].substr(1, currCommand[2].size() - 2));
    std::string recKey = "~" + currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string fresh_str = "Fr(" + recKey + ")";
    rule.ruleNumber = curr_rule;
    if (agent == "TTP") {
        rule.name = "TTP_Step_" + std::to_string(curr_rule);
        rule.agent = "TTP";
        if (curr_rule > 0) {
            rule.ruleCharSet = TTP_rules[curr_rule - 1].ruleCharSet;
            rule.leftPart.push_back(TTP_rules[curr_rule - 1].ruleCharString);
        }
        rule.ruleCharSet.insert(recKey);
        rule.SetToString();
        rule.leftPart.push_back(fresh_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        TTP_rules.push_back(rule);
    } else if (agent == "Ali") {
        rule.name = "Ali_Step_" + std::to_string(curr_rule);
        rule.agent = "Ali";
        if (curr_rule > 0) {
            rule.ruleCharSet = Ali_rules[curr_rule - 1].ruleCharSet;
            rule.leftPart.push_back(Ali_rules[curr_rule - 1].ruleCharString);
        }
        rule.ruleCharSet.insert(recKey);
        rule.SetToString();
        rule.leftPart.push_back(fresh_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Ali_rules.push_back(rule);
    } else if (agent == "Bob") {
        rule.name = "Bob_Step_" + std::to_string(curr_rule);
        rule.agent = "Bob";
        if (curr_rule > 0) {
            rule.ruleCharSet = Bob_rules[curr_rule - 1].ruleCharSet;
            rule.leftPart.push_back(Bob_rules[curr_rule - 1].ruleCharString);
        }
        rule.ruleCharSet.insert(recKey);
        rule.SetToString();
        rule.leftPart.push_back(fresh_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Bob_rules.push_back(rule);
    } else {
        return;
    }
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

void Protocol::ProcessOutPriv(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent, int &curr_rule) {
    Rule rule;
    std::string privMess = currCommand[4].substr(1, currCommand[4].size() - 2);
    if (keys.find(privMess) != keys.end()) {
        privMess = "~" + privMess;
    }
    std::string toAgent = "$" + currCommand[3];
    std::string ltk_str = "!Ltk(" + toAgent + ", " + privMess + ")";
    rule.ruleNumber = curr_rule;
    if (agent == "TTP") {
        rule.name = "TTP_Step_" + std::to_string(curr_rule);
        rule.agent = "TTP";
        if (curr_rule > 0) {
            rule.leftPart.push_back(TTP_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = TTP_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(privMess);
        rule.ruleCharSet.insert(toAgent);
        rule.SetToString();
        rule.rightPart.push_back(ltk_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        TTP_rules.push_back(rule);
    } else if (agent == "Ali") {
        rule.name = "Ali_Step_" + std::to_string(curr_rule);
        rule.agent = "Ali";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Ali_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Ali_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(privMess);
        rule.ruleCharSet.insert(toAgent);
        rule.SetToString();
        rule.rightPart.push_back(ltk_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Ali_rules.push_back(rule);
    } else if (agent == "Bob") {
        rule.name = "Bob_Step_" + std::to_string(curr_rule);
        rule.agent = "Bob";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Bob_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Bob_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(privMess);
        rule.ruleCharSet.insert(toAgent);
        rule.SetToString();
        rule.rightPart.push_back(ltk_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Bob_rules.push_back(rule);
    } else {
        return;
    }
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

//Calc False "f8" "ECMult" ["vCurve","vBasePoint","kXAli_ECScalar4"]

void Protocol::ProcessCalc(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent, int &curr_rule) {
    Rule rule;
    std::string calc_str;
    std::string res_str = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string op_str = currCommand[3].substr(1, currCommand[3].size() - 2);
    if (agent == "TTP") {
        rule.name = "TTP_Step_" + std::to_string(curr_rule);
        rule.agent = "TTP";
        calc_str = op_str + "(";
        for (int i = 5; currCommand[i] != "]"; ++i) {
            std::string currArg = currCommand[i].substr(1, currCommand[i].size() - 2);
            if (keys.find(currArg) != keys.end()) {
                currArg = "~" + currArg;
            } else if (TTP_variables.find(currArg) == TTP_variables.end()) {
                currArg = "\'" + currArg + "\'";
            }
            calc_str += (currArg + ", ");
        }
        calc_str = calc_str.substr(0, calc_str.size() - 2);
        calc_str += ")";
        rule.ruleNumber = curr_rule;
        if (curr_rule > 0) {
            rule.leftPart.push_back(TTP_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = TTP_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(res_str);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        TTP_variables[res_str] = calc_str;
        WriteInLetPartOfRule(rule);
        TTP_rules.push_back(rule);
    } else if (agent == "Ali") {
        rule.name = "Ali_Step_" + std::to_string(curr_rule);
        rule.agent = "Ali";
        calc_str = op_str + "(";
        for (int i = 5; currCommand[i] != "]"; ++i) {
            std::string currArg = currCommand[i].substr(1, currCommand[i].size() - 2);
            if (keys.find(currArg) != keys.end()) {
                currArg = "~" + currArg;
            } else if (Ali_variables.find(currArg) == Ali_variables.end()) {
                currArg = "\'" + currArg + "\'";
            }
            calc_str += (currArg + ", ");
        }
        calc_str = calc_str.substr(0, calc_str.size() - 2);
        calc_str += ")";
        rule.ruleNumber = curr_rule;
        if (curr_rule > 0) {
            rule.leftPart.push_back(Ali_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Ali_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(res_str);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        Ali_variables[res_str] = calc_str;
        WriteInLetPartOfRule(rule);
        Ali_rules.push_back(rule);
    } else if (agent == "TTP") {
        rule.name = "Bob_Step_" + std::to_string(curr_rule);
        rule.agent = "Bob";
        calc_str = op_str + "(";
        for (int i = 5; currCommand[i] != "]"; ++i) {
            std::string currArg = currCommand[i].substr(1, currCommand[i].size() - 2);
            if (keys.find(currArg) != keys.end()) {
                currArg = "~" + currArg;
            } else if (Bob_variables.find(currArg) == Bob_variables.end()) {
                currArg = "\'" + currArg + "\'";
            }
            calc_str += (currArg + ", ");
        }
        calc_str = calc_str.substr(0, calc_str.size() - 2);
        calc_str += ")";
        rule.ruleNumber = curr_rule;
        if (curr_rule > 0) {
            rule.leftPart.push_back(Bob_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Bob_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(res_str);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        Bob_variables[res_str] = calc_str;
        WriteInLetPartOfRule(rule);
        Bob_rules.push_back(rule);
    } else {
        return;
    }
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

void Protocol::ProcessOutPubl(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent, int &curr_rule) {
    Rule rule;
    std::string publMess = currCommand[1].substr(1, currCommand[1].size() - 2);
    std::string outMess = "Out(" + publMess + ")";
    rule.ruleNumber = curr_rule;
    if (agent == "TTP") {
        rule.name = "TTP_Step_" + std::to_string(curr_rule);
        rule.agent = "TTP";
        if (curr_rule > 0) {
            rule.leftPart.push_back(TTP_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = TTP_rules[curr_rule - 1].ruleCharSet;
        }
        rule.rightPart.push_back(outMess);
        rule.ruleCharSet.insert(publMess);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        TTP_rules.push_back(rule);
    } else if (agent == "Ali") {
        rule.name = "Ali_Step_" + std::to_string(curr_rule);
        rule.agent = "Ali";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Ali_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Ali_rules[curr_rule - 1].ruleCharSet;
        }
        rule.rightPart.push_back(outMess);
        rule.ruleCharSet.insert(publMess);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Ali_rules.push_back(rule);
    } else if (agent == "Bob") {
        rule.name = "Bob_Step_" + std::to_string(curr_rule);
        rule.agent = "Bob";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Bob_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Bob_rules[curr_rule - 1].ruleCharSet;
        }
        rule.rightPart.push_back(outMess);
        rule.ruleCharSet.insert(publMess);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Bob_rules.push_back(rule);
    } else {
        return;
    }
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

void Protocol::ProcessInPriv(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent, int &curr_rule) {
    keys.insert(currCommand[5].substr(1, currCommand[5].size() - 2));
    Rule rule;
    std::string privMess = currCommand[5].substr(1, currCommand[5].size() - 2);
    if (keys.find(privMess) != keys.end()) {
        privMess = "~" + privMess;
    }
    std::string fresh_str = "Fr(" + privMess + ")";
    std::string toAgent = "$" + currCommand[3];
    std::string ltk_str = "!Ltk(" + toAgent + ", " + privMess + ")";
    rule.ruleNumber = curr_rule;
    if (agent == "Ali") {
        rule.name = "Ali_Step_" + std::to_string(curr_rule);
        rule.agent = "Ali";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Ali_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Ali_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(privMess);
        rule.ruleCharSet.insert(toAgent);
        rule.SetToString();
        rule.leftPart.push_back(fresh_str);
        rule.rightPart.push_back(ltk_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Ali_rules.push_back(rule);
    } else if (agent == "Bob") {
        rule.name = "Bob_Step_" + std::to_string(curr_rule);
        rule.agent = "Bob";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Bob_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Bob_rules[curr_rule - 1].ruleCharSet;
        }
        rule.ruleCharSet.insert(privMess);
        rule.ruleCharSet.insert(toAgent);
        rule.SetToString();
        rule.leftPart.push_back(fresh_str);
        rule.rightPart.push_back(ltk_str);
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Bob_rules.push_back(rule);
    } else {
        return;
    }
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

// InPubl False "f9"
void Protocol::ProcessInPubl(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent, int &curr_rule) {
    Rule rule;
    std::string publMess = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string inMess = "In(" + publMess + ")";
    rule.ruleNumber = curr_rule;
    if (agent == "Ali") {
        rule.name = "Ali_Step_" + std::to_string(curr_rule);
        rule.agent = "Ali";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Ali_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Ali_rules[curr_rule - 1].ruleCharSet;
        }
        Ali_variables[publMess] = "";
        rule.leftPart.push_back(inMess);
        rule.ruleCharSet.insert(publMess);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Ali_rules.push_back(rule);
    } else if (agent == "Bob") {
        rule.name = "Bob_Step_" + std::to_string(curr_rule);
        rule.agent = "Bob";
        if (curr_rule > 0) {
            rule.leftPart.push_back(Bob_rules[curr_rule - 1].ruleCharString);
            rule.ruleCharSet = Bob_rules[curr_rule - 1].ruleCharSet;
        }
        Bob_variables[publMess] = "";
        rule.leftPart.push_back(inMess);
        rule.ruleCharSet.insert(publMess);
        rule.SetToString();
        rule.rightPart.push_back(rule.ruleCharString);
        WriteInLetPartOfRule(rule);
        Bob_rules.push_back(rule);
    } else {
        return;
    }
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

/*
if (agent == "TTP") {
    auto it = TTP_variables.find(currArg);
    if (it != TTP_variables.end()) {
        letPart[it->first] = ;
    }
}
*/
// ExecuteExpression
void Protocol::ExecuteExpression(const std::string &curr_str, std::ofstream &tamatinOut, const std::string &agent, int &curr_rule) {
    std::vector<std::vector<std::string>> currCommand;
    currCommand = SplitString(curr_str);
    for (int id = 0; id < currCommand.size(); ++id) {
        if (currCommand[id][0] == "Key") {
            ProcessKey(currCommand[id], tamatinOut, agent, curr_rule);
        } else if (currCommand[id][0] == "OutPriv") {
            ProcessOutPriv(currCommand[id], tamatinOut, agent, curr_rule);
        } else if (currCommand[id][0] == "Calc") {
            ProcessCalc(currCommand[id], tamatinOut, agent, curr_rule);
        } else if (currCommand[id][0] == "OutPubl") {
            ProcessOutPubl(currCommand[id], tamatinOut, agent, curr_rule);
        } else if (currCommand[id][0] == "InPriv") {
            ProcessInPriv(currCommand[id], tamatinOut, agent, curr_rule);
        } else if (currCommand[id][0] == "InPubl") {
            ProcessInPubl(currCommand[id], tamatinOut, agent, curr_rule);
        }
        /*
        else if (currCommand[id][0] == "Assign") {
            ProcessAssign(currCommand[id], tamatinOut, curr_rule);
        } else if (currCommand[id][0] == "OutPubl") {
            ProcessOutPubl(currCommand[id], tamatinOut, curr_rule);
        }
        */
    }
}

/*
void Protocol::ExecuteExpressionAgent(const std::string &curr_str, std::ofstream &tamatinOut, std::string agent) {
    std::vector<std::vector<std::string>> currCommand;
    currCommand = SplitString(curr_str);
    for (int id = 0; id < currCommand.size(); ++id) {
        if (currCommand[id][0] == "InPriv") {
            ProcessInPrivAgent(currCommand[id], tamatinOut, agent);
        } else if (currCommand[id][0] == "InPubl") {
            ProcessInPublAgent(currCommand[id], tamatinOut, agent);
        } else if (currCommand[id][0] == "Key") {
            ProcessKeyAgent(currCommand[id], tamatinOut, agent);
        } else if (currCommand[id][0] == "Assign") {
            ProcessAssignAgent(currCommand[id], tamatinOut, agent);
        } else if (currCommand[id][0] == "Calc") {
            ProcessCalcAgent(currCommand[id], tamatinOut, agent);
        }
    }
}

void Protocol::ProcessInPrivAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent) {
    Variable var;
    var.name = currCommand[5];
    var.connect_operation = "Assign";
    std::vector<std::string> source_vec;
    source_vec.push_back(currCommand[5]);
    var.source_operation = source_vec;
    variables[var.name] = var;
    if (agent == "Ali") {
        Ali_variables[var.name] = var;
    } else if (agent == "Bob") {
        Bob_variables[var.name] = var;
    }
}

void Protocol::ProcessInPublAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent) {
    std::string recMess = currCommand[2].substr(1, currCommand[2].size() - 2);
    if (agent == "Ali") {
        std::string rule_name = "InPublAli" + recMess + ":";
        //%%%%%%%%%%%%%%%%%%%%%
        std::vector<std::string> leftPart;
        std::string in_str = "In(" + recMess + ")";
        std::string Ali_str = "!Pk($Ali, pk(" + longKeys.private_key_agent_Ali + "))";
        leftPart.push_back(in_str);
        leftPart.push_back(Ali_str);
        //%%%%%%%%%%%%%%%%%%%%%
        std::vector<std::string> rightPart;
        std::string Ali_comm_str = "Ali(" + recMess + ")";
        rightPart.push_back(Ali_comm_str);
        WriteRule(tamatinOut, rule_name, leftPart, rightPart);
    } else if (agent == "Bob") {
        return;
    }
}

void Protocol::ProcessAssignAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent) {
    std::string recAssing = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string rule_name;
    std::vector<std::string> leftPart;;
    std::string Agent_str;
    std::vector<std::string> rightPart;
    std::string Agent_comm_str;
    if (agent == "Ali") {
        rule_name = "AssignAli_" + recAssing + ":";
        Agent_str = "!Pk($Ali, pk(" + longKeys.private_key_agent_Ali + "))";
        Agent_comm_str = "Ali(" + recAssing + ")";
    } else if (agent == "Bob") {
        return;
    }
    //leftPart.push_back(in_str);
    leftPart.push_back(Agent_str);
    rightPart.push_back(Agent_comm_str);
    WriteRule(tamatinOut, rule_name, leftPart, rightPart);
}

void Protocol::ProcessKeyAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent) {
    std::string recKey = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string rule_name;
    std::vector<std::string> leftPart;
    std::string in_str = "Fr(~" + recKey + ")";
    std::string Agent_str;
    std::vector<std::string> rightPart;
    std::string Agent_comm_str;
    if (agent == "Ali") {
        rule_name = "GenKeyAli_" + recKey + ":";
        Agent_str = "!Pk($Ali, pk(" + longKeys.private_key_agent_Ali + "))";
        Agent_comm_str = "Ali(" + recKey + ")";
    } else if (agent == "Bob") {
        return;
    }
    leftPart.push_back(in_str);
    leftPart.push_back(Agent_str);
    rightPart.push_back(Agent_comm_str);
    WriteRule(tamatinOut, rule_name, leftPart, rightPart);
}

void Protocol::ProcessCalcAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent) {
    std::string resVar = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string rule_name;
    std::vector<std::string> leftPart;
    std::string Agent_str;
    std::vector<std::string> rightPart;
    std::string Agent_comm_str;
    if (agent == "Ali") {
        Agent_str = "!Pk($Ali, pk(" + longKeys.private_key_agent_Ali + "))";
        for (int i = 5; i < currCommand.size() - 1; ++i) {
            std::string leftProp = currCommand[i].substr(1, currCommand[i].size() - 2);
            leftProp = "Ali(" + leftProp + ")";
            leftPart.push_back(leftProp);
        }
        std::string rightExpr;
        for (int i = 5; i < currCommand.size() - 1; ++i) {
            std::string rightProp = currCommand[i].substr(1, currCommand[i].size() - 2);
            rightExpr += rightProp;
            if (i < currCommand.size() - 2) {
                rightExpr += ", ";
            }
        }
        if (currCommand[3] == "Encrypt") {

        }
    }
}
*/
