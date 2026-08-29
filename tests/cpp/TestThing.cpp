#include "TestThing.hpp"

namespace Svc {

// Two levels of private helper before the port invocation, so resolving this
// handler requires following the call graph transitively.
void TestThing::deepHelper() {
    this->alphaOut_out(0, 1);
}

void TestThing::forwardAlpha() {
    this->deepHelper();
}

// Reaches alphaOut through helpers, and tlmOut through a generated helper.
// Must NOT be credited with betaOut.
void TestThing::gIn_handler(int portNum) {
    this->forwardAlpha();
    this->tlmWrite_Count(portNum);
}

// Reaches betaOut only.
void TestThing::sIn_handler(int portNum) {
    this->betaOut_out(0, portNum);
}

// A command handler, keyed as cmd:<MNEMONIC>. Emits an event only.
void TestThing::NOOP_cmdHandler(int opCode) {
    this->log_WARNING_HI_Trouble(opCode);
}

}  // namespace Svc
