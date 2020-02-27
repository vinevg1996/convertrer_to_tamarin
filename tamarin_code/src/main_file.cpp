#include <iostream>
#include "agent.h"

int main(int argc, char **argv) {
    auto NS_agent = std::make_shared<Protocol>("../../NS/base_NS_trace/base_NS_trace.tri", "../../NS/base_NS_trace/base_NS_trace.spthy");
    //auto NS_agent = std::make_shared<Protocol>("../../NS/NS_common_trace/NS1_my_trace_2.tri", "../../NS/NS_common_trace/NS1_my_trace.spthy");

    return 0;
}

/*
// Channel rules
rule ChanOut_S:
    [ Out_S($A,$B,x) ]
    --[ ChanOut_S($A,$B,x) ]->
    [ !Sec($A,$B,x) ]

rule ChanIn_S:
    [ !Sec($A,$B,x) ]
    --[ ChanIn_S($A,$B,x) ]->
    [ In_S($A,$B,x) ]

// Protocol
rule I_1:
    [ Fr(~n) ]
    --[ Send($I,~n), Secret_I(~n) ]->
    [ Out_S($I,$R,~n) ]

rule R_1:
    [ In_S($I,$R,~n) ]
    --[ Secret_R(~n), Authentic($I,~n) ]->
    [ ]
*/