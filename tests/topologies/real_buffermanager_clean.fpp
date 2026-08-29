# Regression topology: real Svc.BufferManager wired the way F' intends.
#
# BufferManager.bufferSendIn, bufferGetCallee and schedIn are all guarded, so
# its handlers run under its mutex.
#
# Note that Svc.EventManager.LogRecv is a *sync* input port, not an async one:
# an event emitted from inside a guarded handler runs EventManager's handler on
# the caller's thread, with the caller's mutex still held. That is fine here
# only because EventManager's own outputs do not reach any guarded port. The
# telemetry path does break the chain, since the sink's receive port is async.
#
# Expected: no lock-order findings.
module RegTest {

  @ A telemetry sink whose receive port is async, unlike Svc.TlmChan
  active component AsyncTlmSink {
    async input port TlmRecv: Fw.Tlm
    time get port timeCaller
  }

  @ A passive time source with a plain sync time port, as most F' time
  @ components use
  passive component SyncTime {
    sync input port timeGetPort: Fw.Time
  }

  instance bufferManager: Svc.BufferManager base id 0x1000

  instance eventManager: Svc.EventManager base id 0x2000 \
    queue size 10 \
    stack size 4096 \
    priority 50

  instance tlmSink: AsyncTlmSink base id 0x3000 \
    queue size 10 \
    stack size 4096 \
    priority 50

  instance timeSource: SyncTime base id 0x4000

  topology BufferManagerClean {
    instance bufferManager
    instance eventManager
    instance tlmSink
    instance timeSource

    connections C {
      bufferManager.eventOut -> eventManager.LogRecv
      bufferManager.tlmOut -> tlmSink.TlmRecv
      bufferManager.timeCaller -> timeSource.timeGetPort
      eventManager.Time -> timeSource.timeGetPort
      tlmSink.timeCaller -> timeSource.timeGetPort
    }
  }
}
