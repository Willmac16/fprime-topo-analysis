# Two distinct urgency drops along one message chain.
#
# 1. Same-queue drop: urgent.hiIn arrives at priority 9 and the handler
#    re-queues onto urgent.loIn at priority 1, on urgent's own queue. The rest
#    of the chain now sits behind every message queued above priority 1.
#
# 2. Task drop: urgent (task priority 90) hands work to sluggish (task
#    priority 10), so end-to-end latency is set by the slower task.
#
# The hop into peer (task priority 95) is an increase, not a drop, and must not
# be reported.
module T {
  port P

  active component Urgent {
    async input port hiIn: P priority 9
    async input port loIn: P priority 1
    output port selfOut: P
    output port downOut: P
    output port upOut: P
  }

  active component Sluggish {
    async input port workIn: P priority 5
  }

  active component Peer {
    async input port workIn: P priority 5
  }

  instance urgent: Urgent base id 0x100 queue size 10 stack size 4096 priority 90
  instance sluggish: Sluggish base id 0x200 queue size 10 stack size 4096 priority 10
  instance peer: Peer base id 0x300 queue size 10 stack size 4096 priority 95

  topology PriorityInversion {
    instance urgent
    instance sluggish
    instance peer

    connections C {
      urgent.selfOut -> urgent.loIn
      urgent.downOut -> sluggish.workIn
      urgent.upOut -> peer.workIn
    }
  }
}
