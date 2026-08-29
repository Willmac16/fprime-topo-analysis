#include "FlowThing.hpp"

namespace RegTest {

// The guarded handler only ever calls outY. It never touches outX, so it can
// never nest partner's mutex inside its own.
void FlowThing::gIn_handler(int portNum) {
    this->outY_out(portNum);
}

// outX is only reachable from the sync handler, which holds no mutex.
void FlowThing::sIn_handler(int portNum) {
    this->outX_out(portNum);
}

void Partner::gIn_handler(int portNum) {
    this->out_out(portNum);
}

// A terminal sink: it invokes nothing.
void Sink::sIn_handler(int portNum) {}

}  // namespace RegTest
