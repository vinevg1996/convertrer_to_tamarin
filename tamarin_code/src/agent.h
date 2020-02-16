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

public:
    Protocol(const std::string &inputFile, 
             const std::string &outputFile);
};

class Agent {
    std::string agent_name;
    std::map<std::string, std::string> variables;
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
                    int &curr_rule);
    void ProcessOutPriv(const std::vector<std::string> &currCommand, 
                    std::ofstream &tamatinOut, 
                    int &curr_rule);
    void ProcessCalc(const std::vector<std::string> &currCommand, 
                     std::ofstream &tamatinOut, 
                     int &curr_rule);
    void ProcessOutPubl(const std::vector<std::string> &currCommand, 
                        std::ofstream &tamatinOut, 
                        int &curr_rule);
    void ProcessInPriv(const std::vector<std::string> &currCommand, 
                       std::ofstream &tamatinOut, 
                       int &curr_rule);
    void ProcessInPubl(const std::vector<std::string> &currCommand, 
                       std::ofstream &tamatinOut,
                       int &curr_rule);
};

#endif