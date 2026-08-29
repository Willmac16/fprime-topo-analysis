# A topology that only looks like an ABBA until the C++ is taken into account.
#
# flowThing has two output ports. Wiring alone allows its guarded handler to
# call outX, which would nest flowThing's mutex inside partner's and close a
# cycle with partner's call back into flowThing.gIn.
#
# The implementation in test/cpp/FlowThing.cpp only ever calls outY from
# gIn_handler. outX is invoked from a different, non-guarded handler. With the
# flow map supplied the edge disappears and so does the cycle.
#
# Expected: ABBA without a flow map, clean with one.
module RegTest {
  port P

  passive component FlowThing {
    guarded input port gIn: P
    sync input port sIn: P
    output port outX: P
    output port outY: P
  }

  passive component Partner {
    guarded input port gIn: P
    output port out: P
  }

  passive component Sink {
    sync input port sIn: P
  }

  instance flowThing: FlowThing base id 0x100
  instance partner: Partner base id 0x200
  instance sink: Sink base id 0x300

  topology FlowPrecision {
    instance flowThing
    instance partner
    instance sink

    connections C {
      flowThing.outX -> partner.gIn
      flowThing.outY -> sink.sIn
      partner.out -> flowThing.gIn
    }
  }
}
