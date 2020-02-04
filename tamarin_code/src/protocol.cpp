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

void Protocol::ReadHeader(std::ifstream &tamatinIn) {
    std::string curr_str;
    while (curr_str != "TTP events:") {
        std::getline(tamatinIn, curr_str);
    }
    std::cout << curr_str << std::endl;
}

void Protocol::WriteHeader(std::ofstream &tamatinOut) {
    tamatinOut << "theory NS1" << std::endl;
    tamatinOut << "begin" << std::endl << std::endl;
    tamatinOut << "builtins:" << std::endl;
    tamatinOut << "    asymmetric-encryption" << std::endl;
    tamatinOut << "    symmetric-encryption" << std::endl;
    tamatinOut << "    diffie-hellman" << std::endl << std::endl;
}

void Protocol::WriteExpressionTTP(std::ofstream &tamatinOut) {
    std::string key_str1 = "    [ Fr(~";
    std::string key_str2 = ") ]";
    std::string str_ltk1 = "    [ !Ltk($Ali, ~";
    std::string str_ltk2 = "), !Pk($Ali, pk(~";
    std::string str_ltk3 = ")) ]";
    std::string str_ltk_1 = "    [ !Ltk($Bob, ~";
    std::string str_ltk_2 = "), !Pk($Bob, pk(~";
    // Ali
    if (longKeys.private_key_agent_Ali.size() > 0) {
        int len_str = longKeys.private_key_agent_Ali.size() - 1;
        longKeys.private_key_agent_Ali = longKeys.private_key_agent_Ali.substr(1, len_str - 1);
        std::string fresh_Ali = key_str1 + longKeys.private_key_agent_Ali + key_str2;
        std::string next_state_Ali = str_ltk1 + longKeys.private_key_agent_Ali
        + str_ltk2 + longKeys.private_key_agent_Ali + str_ltk3;
        
        tamatinOut << "rule Register_AliPk:" << std::endl;
        tamatinOut << fresh_Ali << std::endl;
        tamatinOut << "    -->" << std::endl;
        tamatinOut << next_state_Ali << std::endl << std::endl;
    }
    if (longKeys.public_key_agent_Ali.size() > 0) {
        std::string ali_str_pk1 = "    [ !Pk(Ali, pk(";
        std::string ali_str_pk2 = ")) ]";
        std::string ali_rule_str = ali_str_pk1 + longKeys.private_key_agent_Ali + ali_str_pk2;
        tamatinOut << "rule Get_AliPk:" << std::endl;
        tamatinOut << ali_rule_str << std::endl;
        tamatinOut << "    -->" << std::endl;
        tamatinOut << "    Out(Alipubkey)" << std::endl << std::endl;
    }
    // Bob
    if (longKeys.private_key_agent_Bob.size() > 0) {
        int len_str = longKeys.private_key_agent_Bob.size() - 1;
        longKeys.private_key_agent_Bob = longKeys.private_key_agent_Bob.substr(1, len_str - 1);
        std::string fresh_Bob = key_str1 + longKeys.private_key_agent_Bob + key_str2;
        std::string next_state_Bob = str_ltk_1 + longKeys.private_key_agent_Bob
        + str_ltk_2 + longKeys.private_key_agent_Bob + str_ltk3;
    
        tamatinOut << "rule Register_BobPk:" << std::endl;
        tamatinOut << fresh_Bob << std::endl;
        tamatinOut << "    -->" << std::endl;
        tamatinOut << next_state_Bob << std::endl << std::endl;
    }
    if (longKeys.public_key_agent_Bob.size() > 0) {
        std::string ali_str_pk1 = "    [ !Pk(Ali, pk(";
        std::string ali_str_pk2 = ")) ]";
        std::string ali_rule_str = ali_str_pk1 + longKeys.private_key_agent_Bob + ali_str_pk2;
        tamatinOut << "rule Get_BobPk:" << std::endl;
        tamatinOut << ali_rule_str << std::endl;
        tamatinOut << "    -->" << std::endl;
        tamatinOut << "    Out(Bobpubkey)" << std::endl << std::endl;
    }
}

Protocol::Protocol(const std::string &inputFile, const std::string &outputFile) {
    std::ifstream tamatinIn(inputFile);
    std::ofstream tamatinOut(outputFile);
    ReadHeader(tamatinIn);
    WriteHeader(tamatinOut);
    std::string curr_str;
    // TTP events:
    std::getline(tamatinIn, curr_str);
    while (curr_str != "Ali events:") {
        if (curr_str.size() > 1) {
            ExecuteExpressionTTP(curr_str, tamatinOut);
        }
        std::getline(tamatinIn, curr_str);
    }
    WriteExpressionTTP(tamatinOut);
    // Ali events:
    std::getline(tamatinIn, curr_str);
    while (curr_str != "Bob events:") {
        if (curr_str.size() > 1) {
            ExecuteExpressionAgent(curr_str, tamatinOut, "Ali");
        }
        std::getline(tamatinIn, curr_str);
    }
    
}

// TTP
void Protocol::ExecuteExpressionTTP(const std::string &curr_str, std::ofstream &tamatinOut) {
    std::vector<std::vector<std::string>> currCommand;
    currCommand = SplitString(curr_str);
    for (int id = 0; id < currCommand.size(); ++id) {
        if (currCommand[id][0] == "Key") {
            ProcessKeyTTP(currCommand[id], tamatinOut);
        } else if (currCommand[id][0] == "OutPriv") {
            ProcessOutPrivTTP(currCommand[id], tamatinOut);
        } else if (currCommand[id][0] == "Assign") {
            ProcessAssignTTP(currCommand[id], tamatinOut);
        } else if (currCommand[id][0] == "Calc") {
            ProcessCalcTTP(currCommand[id], tamatinOut);
        } else if (currCommand[id][0] == "OutPubl") {
            ProcessOutPublTTP(currCommand[id], tamatinOut);
        }
    }
}

void Protocol::ProcessKeyTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut) {
    longKeys.private_keys.insert(currCommand[2]);
    return;
}

void Protocol::ProcessOutPrivTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut) {
    if (currCommand[3] == "Ali") {
        auto it = longKeys.private_keys.find(currCommand[4]);
        if (it != longKeys.private_keys.end()) {
            longKeys.private_key_agent_Ali = currCommand[4];
        }
    } else if (currCommand[3] == "Bob") {
        auto it = longKeys.private_keys.find(currCommand[4]);
        if (it != longKeys.private_keys.end()) {
            longKeys.private_key_agent_Bob = currCommand[4];
        }
    }
    return;
}

void Protocol::ProcessAssignTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut) {
    Variable var;
    var.name = currCommand[2];
    var.connect_operation = "Assign";
    std::vector<std::string> source_vec;
    source_vec.push_back(currCommand[3]);
    var.source_operation = source_vec;
    auto it = variables.find(var.name);
    if (it == variables.end()) {
        variables[var.name] = var;
    }
    return;
}

void Protocol::ProcessCalcTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut) {
    Variable var;
    var.name = currCommand[2];
    auto it = variables.find(var.name);
    if (it == variables.end()) {
        var.connect_operation = "Calc";
        std::vector<std::string> source_vec;
        for (int i = 3; i < currCommand.size(); ++i) {
            var.source_operation.push_back(currCommand[i]);
        }
        variables[var.name] = var;
    }
    return;
}

void Protocol::ProcessOutPublTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut) {
    auto it = variables.find(currCommand[1]);
    if (it != variables.end()) {
        if (it->second.source_operation[0] == "\"ECMult\"") {
            std::string pr_key_Ali = longKeys.private_key_agent_Ali;
            auto itAli = std::find(it->second.source_operation.begin(), it->second.source_operation.end(), pr_key_Ali);
            std::string pr_key_Bob = longKeys.private_key_agent_Bob;
            auto itBob = std::find(it->second.source_operation.begin(), it->second.source_operation.end(), pr_key_Bob);
            if (itAli != it->second.source_operation.end()) {
                longKeys.public_key_agent_Ali = it->first;
            }
            if (itBob != it->second.source_operation.end()) {
                longKeys.public_key_agent_Bob = it->first;
            }
        }
    }
}

// Agent

void Protocol::WriteRule(std::ofstream &tamatinOut,
                         const std::string &name, 
                         const std::vector<std::string> &leftPart,
                         const std::vector<std::string> &rightPart) {
    tamatinOut << "rule " << name << ":" << std::endl;
    tamatinOut << "    [ ";
    if (leftPart.size() > 0) {
        for (int i = 0; i < leftPart.size() - 1; ++i) {
            tamatinOut << leftPart[i] << ", ";
        }
        tamatinOut << leftPart[leftPart.size() - 1];
    }
    tamatinOut << " ]" << std::endl;
    tamatinOut << "    -->" << std::endl;
    tamatinOut << "    [ ";
    if (rightPart.size() > 0) {
        for (int i = 0; i < rightPart.size() - 1; ++i) {
            tamatinOut << rightPart[i] << ", ";
        }
        tamatinOut << rightPart[rightPart.size() - 1];
    }
    tamatinOut << " ]" << std::endl << std::endl;
}

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
/*
void Protocol::ProcessCalcAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent) {
    std::string recKey = currCommand[2].substr(1, currCommand[2].size() - 2);
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
        if (currCommand[3]) {

        }
    }
}
*/
// Print
void Protocol::Print() {
    std::cout << "longKeys:" << std::endl;
    std::cout << longKeys.private_key_agent_Ali << std::endl;
    std::cout << longKeys.private_key_agent_Bob << std::endl;
    std::cout << longKeys.public_key_agent_Ali << std::endl;
    std::cout << longKeys.public_key_agent_Bob << std::endl;
    std::cout << "______________________" << std::endl;
}
