#include "DriverTask.hpp"

namespace RegTest {

// Starting the task records SocketHelper::readTask as a thread this component
// spawns - even though the routine and the loop live in the mixin base.
void SocketHelper::startReadTask() {
    Os::Task::Arguments arguments("read", SocketHelper::readTask, this);
    this->m_task.start(arguments);
}

void SocketHelper::readTask(void* pointer) {
    SocketHelper* self = static_cast<SocketHelper*>(pointer);
    self->readLoop();
}

// The loop reaches ports only through virtuals; the base declarations are
// abstract, so resolution must follow the concrete component's overrides.
void SocketHelper::readLoop() {
    int size = this->getBuffer();
    this->sendBuffer(size);
}

void DriverTask::sendBuffer(int size) {
    (void)size;
    this->recv_out(0);
}

int DriverTask::getBuffer() {
    this->allocate_out(0);
    return 0;
}

}  // namespace RegTest
