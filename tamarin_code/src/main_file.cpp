#include <iostream>
#include "agent.h"

int main(int argc, char **argv) {
    auto NS_agent = std::make_shared<Protocol>("../../NS/NS_debug_3.tri", "../../NS/NS_debug.spthy");

    return 0;
}