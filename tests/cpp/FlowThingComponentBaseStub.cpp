#include "FlowThingComponentBaseStub.hpp"

namespace RegTest {

void FlowThingComponentBase::OutputPort::invoke() {}

void FlowThingComponentBase::outX_out(int portNum) {
    this->m_outX_OutputPort[portNum].invoke();
}

void FlowThingComponentBase::outY_out(int portNum) {
    this->m_outY_OutputPort[portNum].invoke();
}

void PartnerComponentBase::OutputPort::invoke() {}

void PartnerComponentBase::out_out(int portNum) {
    this->m_out_OutputPort[portNum].invoke();
}

}  // namespace RegTest
