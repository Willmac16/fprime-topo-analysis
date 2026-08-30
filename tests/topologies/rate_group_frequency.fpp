module T {
  port Work

  passive component Timer {
    output port cycleOut: Svc.Cycle
  }

  passive component Producer {
    sync input port schedIn: Svc.Sched
    output port workOut: Work
  }

  active component Consumer {
    async input port workIn: Work
    output port onward: Work
  }

  passive component Sink {
    sync input port workIn: Work
  }

  instance timer: Timer base id 0x100
  instance driver: Svc.RateGroupDriver base id 0x200
  instance rateGroup: Svc.ActiveRateGroup base id 0x300 \
    queue size 10 \
    stack size 1024 \
    priority 30
  instance producer: Producer base id 0x400
  instance consumer: Consumer base id 0x500 \
    queue size 10 \
    stack size 1024 \
    priority 20
  instance sink: Sink base id 0x600

  topology RateGroupFrequency {
    instance timer
    instance driver
    instance rateGroup
    instance producer
    instance consumer
    instance sink

    connections RateGroup {
      timer.cycleOut -> driver.CycleIn
      driver.CycleOut[0] -> rateGroup.CycleIn
      rateGroup.RateGroupMemberOut[0] -> producer.schedIn
      producer.workOut -> consumer.workIn
      consumer.onward -> sink.workIn
    }
  }
}
