#ifndef FLOW_THING_HPP
#define FLOW_THING_HPP
#include "FlowThingComponentBaseStub.hpp"

namespace RegTest {

class FlowThing : public FlowThingComponentBase {
  protected:
    void gIn_handler(int portNum) override;
    void sIn_handler(int portNum) override;
};

// Partner's guarded handler really does call back into flowThing, so the
// partner -> flowThing lock edge is genuine and must survive.
class Partner : public PartnerComponentBase {
  protected:
    void gIn_handler(int portNum) override;
};

class Sink : public SinkComponentBase {
  protected:
    void sIn_handler(int portNum) override;
};

}  // namespace RegTest
#endif
