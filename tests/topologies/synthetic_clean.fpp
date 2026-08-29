# A one-way guarded call chain. Locks are taken in a single consistent order,
# so there is no cycle.
#
# Expected: no findings.
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
  }
  instance d: Driver base id 0x100 queue size 10 stack size 1024 priority 50
  instance a: CompA base id 0x200
  instance b: CompB base id 0x300
  topology Test {
    instance d
    instance a
    instance b
    connections C {
      d.out -> a.gIn
      a.out -> b.gIn
    }
  }
}
