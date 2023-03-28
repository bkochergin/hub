This program implements a network hub. It takes as its arguments at least two
network interfaces. Each frame received on one of the interfaces will be sent
out to all the other interfaces. Please make sure all the specified interfaces:

  1. Have the same MTU.
  2. Do not have Large Receive Offload (LRO) enabled.
