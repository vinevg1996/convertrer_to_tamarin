#include <iostream>
#include "agent.h"

int main(int argc, char **argv) {
    auto NS_agent = std::make_shared<Protocol>("../../NS/NS_debug.tri", "../../NS/NS_debug.spthy");
	//auto NS_agent = std::make_shared<Protocol>("../../NS/NS_common_trace/NS1_my_trace.tri", "../../NS/NS_common_trace/NS1_my_trace.spthy");

    return 0;
}