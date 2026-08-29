#include "TestComponentBaseStub.hpp"

namespace Svc {

void TestThingComponentBase::OutputPort::invoke(int arg) {}

void TestThingComponentBase::alphaOut_out(int portNum, int arg) {
    this->m_alphaOut_OutputPort[portNum].invoke(arg);
}

void TestThingComponentBase::betaOut_out(int portNum, int arg) {
    this->m_betaOut_OutputPort[portNum].invoke(arg);
}

// Telemetry and event helpers reach their special ports the same way, which is
// how the extractor resolves them without hard-coding helper names.
void TestThingComponentBase::tlmWrite_Count(int value) {
    this->m_tlmOut_OutputPort[0].invoke(value);
}

void TestThingComponentBase::log_WARNING_HI_Trouble(int code) {
    this->m_eventOut_OutputPort[0].invoke(code);
}

}  // namespace Svc
