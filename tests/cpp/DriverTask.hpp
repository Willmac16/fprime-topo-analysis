#ifndef DRIVER_TASK_HPP
#define DRIVER_TASK_HPP
#include "DriverTaskComponentBaseStub.hpp"

// Minimal stand-in for Os::Task, so the extractor sees an Os::Task::Arguments
// construction and the routine handed to it.
namespace Os {
struct Task {
    struct Arguments {
        Arguments(const char* name, void (*routine)(void*), void* arg);
    };
    void start(const Arguments& args);
};
}  // namespace Os

namespace RegTest {

// A mixin like Drv::SocketComponentHelper: it spawns a read task in C++ and
// delivers received data through virtuals its concrete component overrides.
class SocketHelper {
  protected:
    void startReadTask();
    void readLoop();
    static void readTask(void* pointer);
    virtual void sendBuffer(int size) = 0;
    virtual int getBuffer() = 0;
    Os::Task m_task;
};

class DriverTask : public DriverTaskComponentBase, public SocketHelper {
  protected:
    void sendBuffer(int size) override;
    int getBuffer() override;
};

}  // namespace RegTest
#endif
