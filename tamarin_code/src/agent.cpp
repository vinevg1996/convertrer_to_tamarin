#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include "agent.h"
#include "rule.h"

// TTP
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
    tamatinOut << "builtins: asymmetric-encryption," << std::endl;
    tamatinOut << "          hashing" << std::endl << std::endl;
    //tamatinOut << "    asymmetric-encryption" << std::endl;
    //tamatinOut << "    symmetric-encryption" << std::endl;
    //tamatinOut << "    diffie-hellman" << std::endl << std::endl;
    tamatinOut << "functions:" << std::endl;
    tamatinOut << "    ECMult/3," << std::endl;
    tamatinOut << "    Encrypt/2," << std::endl;
    tamatinOut << "    Decrypt/2" << std::endl << std::endl;
    tamatinOut << "equations:" << std::endl;
    tamatinOut << "    Decrypt(Encrypt(mess, ECMult(a, b, key)), key) = mess"
    << std::endl << std::endl;
}

Protocol::Protocol(const std::string &inputFile, 
                   const std::string &outputFile) {
    std::ifstream tamatinIn(inputFile);
    std::ofstream tamatinOut(outputFile);
    ReadHeader(tamatinIn);
    WriteHeader(tamatinOut);
    std::string curr_str;
    int curr_rule = 0;
    // TTP events:
    // Ali events:
    std::getline(tamatinIn, curr_str);
    Agent Ali("Ali");
    while (curr_str != "Bob events:") {
        if (curr_str.size() > 1) {
            Ali.ExecuteExpression(curr_str, tamatinOut, curr_rule);
        }
        std::getline(tamatinIn, curr_str);
    }
    curr_rule = 0;
    Agent Bob("Bob");
    while (std::getline(tamatinIn, curr_str)) {
        if (curr_str.size() > 1) {
            Bob.ExecuteExpression(curr_str, tamatinOut, curr_rule);
        }
        //std::getline(tamatinIn, curr_str);
    }
    curr_rule = 0;
    tamatinOut << "end" << std::endl;
}

// Agent
Agent::Agent(const std::string &agent_name) 
        : agent_name(agent_name) {}

void Agent::ExecuteExpression(const std::string &curr_str, std::ofstream &tamatinOut, int &curr_rule) {
    std::vector<std::vector<std::string>> currCommand;
    currCommand = SplitString(curr_str);
    for (int id = 0; id < currCommand.size(); ++id) {
        if (currCommand[id][0] == "Key") {
            ProcessKey(currCommand[id], tamatinOut, curr_rule);
        } else if (currCommand[id][0] == "InPriv") {
            ProcessInPriv(currCommand[id], tamatinOut, curr_rule);
        } else if (currCommand[id][0] == "Calc") {
            ProcessCalc(currCommand[id], tamatinOut, curr_rule);
        } else if (currCommand[id][0] == "InPubl") {
            ProcessInPubl(currCommand[id], tamatinOut, curr_rule);
        } else if (currCommand[id][0] == "OutPubl") {
            ProcessOutPubl(currCommand[id], tamatinOut, curr_rule);
        }
        /* else if (currCommand[id][0] == "OutPriv") {
            ProcessOutPriv(currCommand[id], tamatinOut, curr_rule);
        }
        */
    }
}

void Agent::WriteInLetPartOfRule(Rule &rule) {
    for (const auto &elem: rule.ruleCharSet) {
        auto it = variables.find(elem);
        if ((it != variables.end()) && (it->second.size() > 0)) {
            rule.letPart[it->first] = it->second;
        }
    }
}

void Agent::ProcessKey(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, int &curr_rule) {
    Rule rule;
    keys.insert(currCommand[2].substr(1, currCommand[2].size() - 2));
    std::string recKey = "~" + currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string fresh_str = "Fr(" + recKey + ")";
    rule.ruleNumber = curr_rule;
    rule.name = agent_name + "_Step_" + std::to_string(curr_rule);
    rule.agent = agent_name;
    if (curr_rule > 0) {
        rule.ruleCharSet = rulesStack[curr_rule - 1].ruleCharSet;
        rule.leftPart.push_back(rulesStack[curr_rule - 1].ruleCharString);
    }
    rule.ruleCharSet.insert(recKey);
    rule.SetToString();
    rule.leftPart.push_back(fresh_str);
    rule.actionPart = recKey;
    rule.rightPart.push_back(rule.ruleCharString);
    WriteInLetPartOfRule(rule);
    rulesStack.push_back(rule);
    
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

void Agent::ProcessInPriv(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, int &curr_rule) {
    keys.insert(currCommand[5].substr(1, currCommand[5].size() - 2));
    Rule rule;
    std::string privMess = currCommand[5].substr(1, currCommand[5].size() - 2);
    if (keys.find(privMess) != keys.end()) {
        privMess = "~" + privMess;
    }
    std::string fresh_str = "Fr(" + privMess + ")";
    //std::string toAgent = "$" + currCommand[3];
    //std::string ltk_str = "!Ltk(" + toAgent + ", " + privMess + ")";
    rule.ruleNumber = curr_rule;
    rule.name = agent_name + "_Step_" + std::to_string(curr_rule);
    rule.agent = agent_name;
    
    if (curr_rule > 0) {
        rule.leftPart.push_back(rulesStack[curr_rule - 1].ruleCharString);
        rule.ruleCharSet = rulesStack[curr_rule - 1].ruleCharSet;
    }
    rule.ruleCharSet.insert(privMess);
    //rule.ruleCharSet.insert(toAgent);
    rule.SetToString();
    rule.leftPart.push_back(fresh_str);
    rule.actionPart = privMess;
    //rule.rightPart.push_back(ltk_str);
    rule.rightPart.push_back(rule.ruleCharString);
    WriteInLetPartOfRule(rule);
    rulesStack.push_back(rule);

    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

void Agent::ProcessCalc(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, int &curr_rule) {
    Rule rule;
    std::string calc_str;
    std::string res_str = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string op_str = currCommand[3].substr(1, currCommand[3].size() - 2);

    rule.name = agent_name + "_Step_" + std::to_string(curr_rule);
    rule.agent = agent_name;
    calc_str = op_str + "(";
    for (int i = 5; currCommand[i] != "]"; ++i) {
        std::string currArg = currCommand[i].substr(1, currCommand[i].size() - 2);
        if (keys.find(currArg) != keys.end()) {
            currArg = "~" + currArg;
        } else if (variables.find(currArg) == variables.end()) {
            currArg = "\'" + currArg + "\'";
        }
        calc_str += (currArg + ", ");
    }
    calc_str = calc_str.substr(0, calc_str.size() - 2);
    calc_str += ")";
    rule.ruleNumber = curr_rule;
    if (curr_rule > 0) {
        rule.leftPart.push_back(rulesStack[curr_rule - 1].ruleCharString);
        rule.ruleCharSet = rulesStack[curr_rule - 1].ruleCharSet;
    }
    rule.ruleCharSet.insert(res_str);
    rule.SetToString();
    rule.actionPart = res_str;
    rule.rightPart.push_back(rule.ruleCharString);
    variables[res_str] = calc_str;
    WriteInLetPartOfRule(rule);
    rulesStack.push_back(rule);

    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

void Agent::ProcessInPubl(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, int &curr_rule) {
    Rule rule;
    std::string publMess = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string inMess = "In(" + publMess + ")";
    rule.ruleNumber = curr_rule;
    rule.name = agent_name + "_Step_" + std::to_string(curr_rule);
    rule.agent = agent_name;
    if (curr_rule > 0) {
        rule.leftPart.push_back(rulesStack[curr_rule - 1].ruleCharString);
        rule.ruleCharSet = rulesStack[curr_rule - 1].ruleCharSet;
    }
    variables[publMess] = "";
    rule.leftPart.push_back(inMess);
    rule.ruleCharSet.insert(publMess);
    rule.SetToString();
    rule.actionPart = publMess;
    rule.rightPart.push_back(rule.ruleCharString);
    WriteInLetPartOfRule(rule);
    rulesStack.push_back(rule);
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}

void Agent::ProcessOutPubl(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, int &curr_rule) {
    Rule rule;
    std::string publMess = currCommand[1].substr(1, currCommand[1].size() - 2);
    std::string outMess = "Out(" + publMess + ")";
    rule.ruleNumber = curr_rule;    
    rule.name = agent_name + "_Step_" + std::to_string(curr_rule);
    rule.agent = agent_name;
    if (curr_rule > 0) {
        rule.leftPart.push_back(rulesStack[curr_rule - 1].ruleCharString);
        rule.ruleCharSet = rulesStack[curr_rule - 1].ruleCharSet;
    }
    rule.rightPart.push_back(outMess);
    rule.ruleCharSet.insert(publMess);
    rule.SetToString();
    rule.actionPart = publMess;
    rule.rightPart.push_back(rule.ruleCharString);
    WriteInLetPartOfRule(rule);
    rulesStack.push_back(rule);
    rule.WriteRule(tamatinOut);
    ++curr_rule;
}
