#ifndef AGENT
#define AGENT

#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <memory>
#include "rule.h"

class Protocol {

    void ReadHeader(std::ifstream &tamarinIn);
    void WriteHeader(std::ofstream &tamatinOut);
    void CreateSecureChannels(std::ofstream &tamatinOut);

public:
    Protocol(const std::string &inputFile, 
             const std::string &outputFile);
};

class Agent {
    std::string agent_name;
    std::map<std::string, std::string> variables;
    std::vector<std::string> var_order;
    std::vector<Rule> rulesStack;
    std::set<std::string> keys;

public:
    Agent(const std::string &agent_name);
    void ExecuteExpression(const std::string &curr_str, 
                           std::ofstream &tamatinOut, 
                           int &curr_rule);
    void WriteInLetPartOfRule(Rule &rule);
    void ProcessKey(const std::vector<std::string> &currCommand, 
                    std::ofstream &tamatinOut, 
                    Rule &currRule);
    void ProcessInPriv(const std::vector<std::string> &currCommand, 
                       std::ofstream &tamatinOut, 
                       Rule &currRule);
    void ProcessOutPriv(const std::vector<std::string> &currCommand, 
                        std::ofstream &tamatinOut, 
                        Rule &currRule);
    void ProcessCalc(const std::vector<std::string> &currCommand, 
                     std::ofstream &tamatinOut, 
                     Rule &currRule);
    void ProcessAssign(const std::vector<std::string> &currCommand, 
                       std::ofstream &tamatinOut, 
                       Rule &currRule);
    void ProcessInPubl(const std::vector<std::string> &currCommand, 
                       std::ofstream &tamatinOut, 
                       Rule &currRule);
    void ProcessOutPubl(const std::vector<std::string> &currCommand, 
                        std::ofstream &tamatinOut, 
                        Rule &currRule);
    void ProcessRevConcat(const std::vector<std::string> &currCommand, 
                          std::ofstream &tamatinOut, 
                          Rule &currRule);
};

#endif