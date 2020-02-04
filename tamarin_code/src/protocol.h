#ifndef PROTOCOL
#define PROTOCOL

#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <memory>

struct LongAsymmetricKeys {
    std::set<std::string> private_keys;
    std::string private_key_agent_Ali;
    std::string private_key_agent_Bob;
    std::string public_key_agent_Ali;
    std::string public_key_agent_Bob;
};

struct EphemerAsymmetricKeys {
    std::vector<std::string> private_keys_agent_Ali;
    std::vector<std::string> private_keys_agent_Bob;
    std::vector<std::string> public_keys_agent_Ali;
    std::vector<std::string> public_keys_agent_Bob;
};

struct SymmetricKeys {
    std::vector<std::string> plain_keys_agent_Ali;
    std::vector<std::string> plain_keys_agent_Bob;
};

struct Nonces {
    std::vector<std::string> nonces_agent_Ali;
    std::vector<std::string> nonces_agent_Bob;
};

// result of Calc operation
struct Variable {
    std::string name;
    std::string connect_operation;
    std::vector<std::string> source_operation;
};

struct Operation {
    std::string name;
    int arity;
};
/*
class Expression {
    std::string Agent;

public:
};
*/

std::vector<std::string> SplitOperationString(const std::string &curr_str, int start, int &end);

std::vector<std::vector<std::string>> SplitString(const std::string &curr_str);

class Protocol {
    LongAsymmetricKeys longKeys;
    EphemerAsymmetricKeys ephemerKeys;
    SymmetricKeys symmKeys;
    Nonces nonces;
    //std::map<std::string, Variable> constants;
    std::map<std::string, Variable> variables;
    std::map<std::string, Variable> Ali_variables;
    std::map<std::string, Variable> Bob_variables;
    std::vector<Operation> operations;

    void ReadHeader(std::ifstream &tamarinIn);
    void WriteHeader(std::ofstream &tamatinOut);
    // TTP
    void ProcessKeyTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut);
    void ProcessOutPrivTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut);
    void ProcessAssignTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut);
    void ProcessCalcTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut);
    void ProcessOutPublTTP(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut);
    // Agent
    void ProcessInPrivAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent);
    void ProcessInPublAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent);
    void ProcessKeyAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent);
    void ProcessAssignAgent(const std::vector<std::string> &currCommand, std::ofstream &tamatinOut, std::string agent);

    void WriteRule(std::ofstream &tamatinOut,
                   const std::string &name, 
                   const std::vector<std::string> &leftPart,
                   const std::vector<std::string> &rightPart);

public:
    Protocol(const std::string &inputFile, const std::string &outputFile);
    //Expression ExecuteExpressionTTP();
    void ExecuteExpressionTTP(const std::string &curr_str, std::ofstream &tamatinOut);
    void WriteExpressionTTP(std::ofstream &tamatinOut);
    void ExecuteExpressionAgent(const std::string &curr_str, std::ofstream &tamatinOut, std::string agent);
    void Print();
};

#endif