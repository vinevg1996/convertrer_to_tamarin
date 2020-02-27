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
    tamatinOut << "theory NS_ATACK_DEBUG" << std::endl;
    tamatinOut << "begin" << std::endl << std::endl;
    tamatinOut << "builtins: asymmetric-encryption," << std::endl;
    tamatinOut << "          hashing" << std::endl << std::endl;
    tamatinOut << "functions:" << std::endl;
    tamatinOut << "    ECMult/3," << std::endl;
    tamatinOut << "    Encrypt/2," << std::endl;
    tamatinOut << "    Decrypt/2," << std::endl;
    tamatinOut << "    mFirstHalf/1," << std::endl;
    tamatinOut << "    LengthBE2/1," << std::endl;
    tamatinOut << "    ModMult/3," << std::endl;
    tamatinOut << "    ModDiv0/3," << std::endl;
    tamatinOut << "    EncryptAES192/3," << std::endl;
    tamatinOut << "    DecryptAES192/3" << std::endl << std::endl;
    tamatinOut << "equations:" << std::endl;
    tamatinOut << "    Decrypt(Encrypt(mess, ECMult(a, b, key)), key) = mess," << std::endl;
    tamatinOut << "    ModDiv0(ModMult(a0, a1, a2), a1, a2) = a0," << std::endl;
    tamatinOut << "    DecryptAES192(EncryptAES192(a0, a1, a2), a1, a2) = a0" << std::endl
    << std::endl;
}

void Protocol::CreateSecureChannels(std::ofstream &tamatinOut) {
    Rule inChanRule, outChanRule;
    // outChanRule
    outChanRule.name = "ChanOut_S";
    std::string left_str = "SecureOut($A, $B, x)";
    outChanRule.leftPart.push_back(left_str);
    std::string action_str = "SecureOut($A, $B, x)";
    outChanRule.actionPart.insert(action_str);
    std::string right_str = "!SecureTransmission($A, $B, x)";
    outChanRule.rightPart.push_back(right_str);
    outChanRule.WriteRule(tamatinOut);
    // InChanRule
    inChanRule.name = "ChanIn_S";
    inChanRule.leftPart.push_back(right_str);
    std::string in_action_str = "SecureIn($A, $B, x)";
    inChanRule.actionPart.insert(in_action_str);
    std::string in_right_str = "SecureIn($A, $B, x)";
    inChanRule.rightPart.push_back(in_right_str);
    inChanRule.WriteRule(tamatinOut);
    return;
}

Protocol::Protocol(const std::string &inputFile, 
                   const std::string &outputFile) {
    std::ifstream tamatinIn(inputFile);
    std::ofstream tamatinOut(outputFile);
    ReadHeader(tamatinIn);
    WriteHeader(tamatinOut);
    CreateSecureChannels(tamatinOut);
    std::string curr_str;
    int curr_rule = 0;
    // TTP events:
    std::getline(tamatinIn, curr_str);
    Agent TTP("TTP");
    while (curr_str != "Ali events:") {
        if (curr_str.size() > 1) {
            TTP.ExecuteExpression(curr_str, tamatinOut, curr_rule);
        }
        std::getline(tamatinIn, curr_str);
    }
    curr_rule = 0;
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
    tamatinOut << std::endl << "//lemmas:" 
    << std::endl << std::endl << std::endl;
    tamatinOut << "end" << std::endl;
}

// Agent
Agent::Agent(const std::string &agent_name) 
        : agent_name(agent_name) {}

void Agent::ExecuteExpression(const std::string &curr_str, std::ofstream &tamatinOut, int &curr_rule) {
    std::vector<std::vector<std::string>> currCommand;
    currCommand = SplitString(curr_str);
    Rule currRule;
    currRule.ruleNumber = curr_rule;
    currRule.name = agent_name + "_Step_" + std::to_string(curr_rule);
    currRule.agent = agent_name;
    if (currRule.ruleNumber > 0) {
        currRule.ruleCharSet = rulesStack[curr_rule - 1].ruleCharSet;
        currRule.leftPart.push_back(rulesStack[curr_rule - 1].ruleCharString);
    }

    for (int id = 0; id < currCommand.size(); ++id) {
        /*
        for (int j = 0; j < currCommand[id].size(); ++j) {
            std::cout << currCommand[id][j] << " ";
        }
        std::cout << std::endl;
        */
        if (currCommand[id][0] == "Key") {
            ProcessKey(currCommand[id], tamatinOut, currRule);
        } else if (currCommand[id][0] == "InPriv") {
            ProcessInPriv(currCommand[id], tamatinOut, currRule);
        } else if (currCommand[id][0] == "OutPriv") {
            ProcessOutPriv(currCommand[id], tamatinOut, currRule);
        } else if (currCommand[id][0] == "Calc") {
            ProcessCalc(currCommand[id], tamatinOut, currRule);
        } else if (currCommand[id][0] == "Assign") {
            ProcessAssign(currCommand[id], tamatinOut, currRule);
        } else if (currCommand[id][0] == "InPubl") {
            ProcessInPubl(currCommand[id], tamatinOut, currRule);
        } else if (currCommand[id][0] == "OutPubl") {
            ProcessOutPubl(currCommand[id], tamatinOut, currRule);
        } else if (currCommand[id][0] == "RevConcat") {
            ProcessRevConcat(currCommand[id], tamatinOut, currRule);
        }
    }
    currRule.SetToString();
    currRule.rightPart.push_back(currRule.ruleCharString);
    WriteInLetPartOfRule(currRule);
    rulesStack.push_back(currRule);
    currRule.WriteRule(tamatinOut);
    ++curr_rule;
    return;
}

void Agent::WriteInLetPartOfRule(Rule &rule) {
    for (int i = 0; i < var_order.size(); ++i) {
        auto it1 = rule.ruleCharSet.find(var_order[i]);
        auto it = variables.find(var_order[i]);
        if ((it1 != rule.ruleCharSet.end()) && (it->second.size() > 0)) {
            std::string new_string = *it1 + " = " + it->second;
            rule.letPart.push_back(new_string);
        }
    }
}

void Agent::ProcessKey(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    keys.insert(currCommand[2].substr(1, currCommand[2].size() - 2));
    std::string recKey = "~" + currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string fresh_str = "Fr(" + recKey + ")";
    
    currRule.ruleCharSet.insert(recKey);
    currRule.leftPart.push_back(fresh_str);
    //rule.actionPart = recKey;
}
/*
void Agent::ProcessInPriv(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    keys.insert(currCommand[5].substr(1, currCommand[5].size() - 2));
    std::string privMess = currCommand[5].substr(1, currCommand[5].size() - 2);
    if (keys.find(privMess) != keys.end()) {
        privMess = "~" + privMess;
    }
    std::string fresh_str = "Fr(" + privMess + ")";

    currRule.ruleCharSet.insert(privMess);
    currRule.leftPart.push_back(fresh_str);
}
*/

// [InPriv 1 TTP Ali False "kXAli_ECScalar4"]
void Agent::ProcessInPriv(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    keys.insert(currCommand[5].substr(1, currCommand[5].size() - 2));
    std::string privMess = currCommand[5].substr(1, currCommand[5].size() - 2);
    if (keys.find(privMess) != keys.end()) {
        privMess = "~" + privMess;
    }
    std::string agent_from = currCommand[2];
    std::string agent_to = currCommand[3];
    std::string sec_in_str = "SecureIn($" + agent_from + ", "
    + "$" + agent_to + ", " + privMess + ")";

    currRule.ruleCharSet.insert(privMess);
    currRule.leftPart.push_back(sec_in_str);
}

// OutPriv 1 TTP Ali "kXAli_ECScalar4"
// [OutPriv 2 TTP Ali "f9"]
void Agent::ProcessOutPriv(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    //keys.insert(currCommand[5].substr(1, currCommand[5].size() - 2));
    std::string privMess = currCommand[4].substr(1, currCommand[4].size() - 2);
    std::string oldPrivMess = privMess;
    if (keys.find(privMess) != keys.end()) {
        privMess = "~" + privMess;
    }
    std::string agent_from = currCommand[2];
    std::string agent_to = currCommand[3];
    std::string sec_out_str = "SecureOut($" + agent_from + ", "
    + "$" + agent_to + ", " + privMess + ")";
    std::string sec_char_str = "SecureOut_" + agent_from + "_"
    + agent_to + "_" + oldPrivMess;
    
    //currRule.ruleCharSet.insert(sec_char_str);
    currRule.rightPart.push_back(sec_out_str);
}

void Agent::ProcessCalc(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    std::string calc_str;
    std::string res_str = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string op_str = currCommand[3].substr(1, currCommand[3].size() - 2);
    if (currCommand[1] == "True") {
        calc_str = op_str;
        calc_str += "(";
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
        std::string actionStr = "Eq(" + res_str + ", " + calc_str + ")";
        currRule.actionPart.insert(actionStr);
        return;
    } else {
        if (op_str == "Concat") {
        calc_str = "<";
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
        calc_str += ">";
        } else {
            calc_str = op_str;
            calc_str += "(";
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
        }
        currRule.ruleCharSet.insert(res_str);
        //rule.actionPart = res_str;
        variables[res_str] = calc_str;
        var_order.push_back(res_str);
    }
}

//Assign False "vCurve" "x2a8648ce3d030101"
void Agent::ProcessAssign(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    std::string var_str = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string value_str = currCommand[3].substr(1, currCommand[3].size() - 2);
    currRule.ruleCharSet.insert(var_str);
    //rule.actionPart = res_str;
    if (variables.find(value_str) == variables.end()) {
        value_str = "\'" + value_str + "\'";
    }
    variables[var_str] = value_str;
    var_order.push_back(var_str);
}

void Agent::ProcessInPubl(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    std::string publMess = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string inMess = "In(" + publMess + ")";
    variables[publMess] = "";
    var_order.push_back(publMess);
    currRule.leftPart.push_back(inMess);
    currRule.ruleCharSet.insert(publMess);
    //rule.actionPart = publMess;
}

// RevConcat [ ("f21" False) ("f20" False) ]  "f22"
//RevConcat
//[
//("kN_Nonce24"
//False)
//("f26"
//False)
//]
//"f22"
void Agent::ProcessRevConcat(const std::vector<std::string> &currCommand, 
                             std::ofstream &tamatinOut, 
                             Rule &currRule) {
    std::string calc_str;
    std::string res_str = currCommand[2].substr(1, currCommand[2].size() - 2);
    std::string op_str = currCommand[3].substr(1, currCommand[3].size() - 2);
    calc_str = op_str;
    calc_str += "(";
    std::string from_str = currCommand[currCommand.size() - 1];
    from_str = from_str.substr(1, from_str.size() - 2);
    //std::string extract_str = "fst(";
    std::string extract_str;
    int count = 0;
    for (int i = 2; currCommand[i] != "]"; i = i + 2) {
        std::string currArg = currCommand[i].substr(2, currCommand[i].size() - 3);
        if (count > 0) {
            extract_str = "snd(" + extract_str;
        }
        //extract_str = extract_str + from_str;
        std::string right_str = extract_str + from_str;
        for (int br = 0; br < count; ++br) {
            right_str = right_str + ")";
        }
        if (currCommand[i + 2] != "]") {
            right_str = "fst(" + right_str + ")";
        }
        std::string var_str = currArg + " = " + right_str;
        currRule.ruleCharSet.insert(currArg);
        variables[currArg] = right_str;
        var_order.push_back(currArg);
        ++count;
    }

}

void Agent::ProcessOutPubl(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, Rule &currRule) {
    std::string publMess = currCommand[1].substr(1, currCommand[1].size() - 2);
    std::string outMess = "Out(" + publMess + ")";
    currRule.rightPart.push_back(outMess);
    currRule.ruleCharSet.insert(publMess);
    //rule.actionPart = publMess;
}
