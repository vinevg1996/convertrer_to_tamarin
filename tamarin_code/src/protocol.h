#ifndef PROTOCOL
#define PROTOCOL

#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <memory>

std::vector<std::string> SplitOperationString(const std::string &curr_str, int start, int &end);

std::vector<std::vector<std::string>> SplitString(const std::string &curr_str);

struct Rule {
    std::string name;
    int ruleNumber;
    std::string agent;
    std::set<std::string> ruleCharSet;
    std::string ruleCharString;
    std::vector<std::string> leftPart;
    std::vector<std::string> rightPart;
    std::map<std::string, std::string> letPart;

    void SetToString();
    void WriteLetPart(std::ofstream &tamatinOut);
    void WriteRule(std::ofstream &tamatinOut);
};

class Protocol {
    std::map<std::string, std::string> TTP_variables;
    std::map<std::string, std::string> Ali_variables;
    std::map<std::string, std::string> Bob_variables;
    std::vector<Rule> TTP_rules;
    std::vector<Rule> Ali_rules;
    std::vector<Rule> Bob_rules;
    std::set<std::string> keys;

    void ReadHeader(std::ifstream &tamarinIn);
    void WriteHeader(std::ofstream &tamatinOut);
    void WriteInLetPartOfRule(Rule &rule);
    void ProcessKey(const std::vector<std::string> &currCommand, 
                    std::ofstream &tamatinOut, 
                    std::string agent,
                    int &curr_rule);
    void ProcessOutPriv(const std::vector<std::string> &currCommand, 
                        std::ofstream &tamatinOut, 
                        std::string agent,
                        int &curr_rule);
    void ProcessCalc(const std::vector<std::string> &currCommand, 
                     std::ofstream &tamatinOut, 
                     std::string agent,
                     int &curr_rule);
    void ProcessOutPubl(const std::vector<std::string> &currCommand, 
                        std::ofstream &tamatinOut, 
                        std::string agent,
                        int &curr_rule);
    void ProcessInPriv(const std::vector<std::string> &currCommand, 
                       std::ofstream &tamatinOut, 
                       std::string agent,
                       int &curr_rule);
    void ProcessInPubl(const std::vector<std::string> &currCommand, 
                       std::ofstream &tamatinOut, 
                       std::string agent,
                       int &curr_rule);
    /*
    void ProcessAssign(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent);
    void ProcessInPriv(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent);
    void ProcessInPubl(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent);
    */

public:
    Protocol(const std::string &inputFile, const std::string &outputFile);
    void ExecuteExpression(const std::string &curr_str, std::ofstream &tamatinOut, const std::string &agent, int &curr_rule);
    std::vector<Rule> Get_TTP_rules() {
        return TTP_rules;
    }
    std::vector<Rule> Get_Ali_rules() {
        return Ali_rules;
    }
    std::vector<Rule> Get_Bob_rules() {
        return Bob_rules;
    }
};

#endif