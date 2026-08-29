# Regression topology: a real Svc.TlmChan wired into a lock-order cycle.
#
# Svc.TlmChan.TlmRecv and Svc.TlmChan.TlmGet are both guarded input ports, and
# TlmChan reaches back out through its time get port. A time provider whose
# time port is guarded and which itself writes telemetry closes the loop:
#
#   TlmChan (guarded TlmRecv) -> timeCaller -> TimeKeeper (guarded)
#   TimeKeeper -> tlmOut -> TlmChan (guarded TlmRecv)
#
# Expected: a lock-order cycle between tlmChan and timeKeeper.
module RegTest {

  @ A time provider that guards its time port and also emits telemetry
  passive component GuardedTimeKeeper {
    guarded input port timeGetPort: Fw.Time
    telemetry port tlmOut
    time get port timeCaller
    telemetry TimeReads: U32
  }

  instance tlmChan: Svc.TlmChan base id 0x1000 \
    queue size 10 \
    stack size 4096 \
    priority 50

  instance timeKeeper: GuardedTimeKeeper base id 0x2000

  topology TlmChanCycle {
    instance tlmChan
    instance timeKeeper

    connections C {
      tlmChan.timeCaller -> timeKeeper.timeGetPort
      timeKeeper.tlmOut -> tlmChan.TlmRecv
      timeKeeper.timeCaller -> timeKeeper.timeGetPort
    }
  }
}
