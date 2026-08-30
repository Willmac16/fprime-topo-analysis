module T {
  active component CommandTarget {
    command recv port cmdIn
    command reg port cmdRegOut
    command resp port cmdResponseOut

    async command DISCARD priority 9 drop
    async command KEEP priority 3 assert
  }

  passive component CommandSource {
    output port cmdOut: Fw.Cmd
  }

  instance target: CommandTarget base id 0x100 \
    queue size 10 \
    stack size 1024 \
    priority 50
  instance source: CommandSource base id 0x200

  topology CommandQueueBehavior {
    instance target
    instance source

    connections Commands {
      source.cmdOut -> target.cmdIn
    }
  }
}
