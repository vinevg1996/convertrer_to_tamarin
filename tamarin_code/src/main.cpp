#include <iostream>
#include "protocol.h"

int main(int argc, char **argv) {
    Protocol NS("../../NS/NS_debug.tri", "../../NS/NS_debug.spthy");
    NS.Print();
    return 0;
}