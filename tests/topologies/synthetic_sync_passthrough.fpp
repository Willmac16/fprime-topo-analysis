# A guarded component calls through a *sync* component into another guarded
# component. A sync input port takes no mutex of its own but runs on the
# caller's thread, so the lock chain must survive the hop: the cycle is between
# a and c, and p must not appear as a lock holder.
#
# Expected: a lock-order cycle a -> c -> a that does not include p.
module T {
  port P
  passive component CompA {
    guarded input port gIn: P
    output port out: P
  }
  passive component Pass {
    sync input port sIn: P
    output port out: P
  }
  passive component CompC {
    guarded input port gIn: P
    output port out: P
  }
  instance a: CompA base id 0x100
  instance p: Pass base id 0x200
  instance c: CompC base id 0x300
  topology Test {
    instance a
    instance p
    instance c
    connections C {
      a.out -> p.sIn
      p.out -> c.gIn
      c.out -> a.gIn
    }
  }
}
