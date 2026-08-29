# Two all-guarded components reaching into each other, each driven by its own
# thread. This is the canonical ABBA shape: one thread enters through a and
# locks a-then-b, the other enters through b and locks b-then-a.
#
# Expected: an ABBA cycle between a and b, plus the self-deadlock each chain
# hits when it completes a full round trip on one thread.
module T {
  port P
  active component Driver {
    async input port wake: P
    output port out: P
  }
  passive component CompA {
    guarded input port gIn: P
    output port out: P
  }
  passive component CompB {
    guarded input port gIn: P
    output port out: P
  }
  instance d1: Driver base id 0x100 queue size 10 stack size 1024 priority 50
  instance d2: Driver base id 0x200 queue size 10 stack size 1024 priority 50
  instance a: CompA base id 0x300
  instance b: CompB base id 0x400
  topology Test {
    instance d1
    instance d2
    instance a
    instance b
    connections C {
      d1.out -> a.gIn
      d2.out -> b.gIn
      a.out -> b.gIn
      b.out -> a.gIn
    }
  }
}
