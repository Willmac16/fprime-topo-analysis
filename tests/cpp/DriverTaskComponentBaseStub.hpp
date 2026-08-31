// Named ...BaseStub rather than ...Ac because the repository ignores *Ac.*
// as autocode. The extractor keys on the ComponentBase class name, not the file.
#ifndef DRIVER_TASK_AC_HPP
#define DRIVER_TASK_AC_HPP

namespace RegTest {

class DriverTaskComponentBase {
  protected:
    void recv_out(int portNum);
    void allocate_out(int portNum);
    void ready_out(int portNum);
};

}  // namespace RegTest
#endif
