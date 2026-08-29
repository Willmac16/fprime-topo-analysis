#ifndef TEST_THING_HPP
#define TEST_THING_HPP
#include "TestComponentBaseStub.hpp"

namespace Svc {

class TestThing : public TestThingComponentBase {
  protected:
    void gIn_handler(int portNum) override;
    void sIn_handler(int portNum) override;
    void NOOP_cmdHandler(int opCode) override;

  private:
    void forwardAlpha();
    void deepHelper();
};

}  // namespace Svc
#endif
