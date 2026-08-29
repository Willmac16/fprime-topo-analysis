# The same two-component loop as synthetic_abba, except the return hop lands on
# an async input port. The message is queued and the caller's mutex is released
# before it is serviced, so the locks never nest.
#
# Expected: no findings. This is the primary false-positive guard.
module T {
  port P
  passive component CompA {
    guarded input port gIn: P
    output port out: P
  }
  active component CompB {
    async input port aIn: P
    output port out: P
  }
  instance a: CompA base id 0x100
  instance b: CompB base id 0x200 queue size 10 stack size 1024 priority 50
  topology Test {
    instance a
    instance b
    connections C {
      a.out -> b.aIn
      b.out -> a.gIn
    }
  }
}
