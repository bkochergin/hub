/*
 * Copyright 2023 Boris Kochergin. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>
#include <vector>

#include <pcap.h>

using namespace std;

int main(int argc, char* argv[]) {
  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " interface ..." << endl;
    return EXIT_FAILURE;
  }
  if (argc < 3) {
    cerr << "Must specify at least two interfaces." << endl;
    return EXIT_FAILURE;
  }

  // Open all interfaces.
  vector<pcap_t*> pcap_descriptors;
  for (int i = 1; i < argc; ++i) {
    const char* interface = argv[i];

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_descriptor =
        pcap_open_live(
            interface,
            /* Snapshot length. */ numeric_limits<uint16_t>::max(),
            /* Promiscuous mode. */ 1, /* Read timeout (ms). */ 10,
            error_buffer);
    if (pcap_descriptor == nullptr) {
      cerr << "Could not open " << interface << ": " << error_buffer << endl;
      return EXIT_FAILURE;
    }

    // Only capture incoming traffic. Otherwise, we'd capture frames we've
    // sent out and cause a forwarding loop.
    if (pcap_setdirection(pcap_descriptor, PCAP_D_IN) != 0) {
      cerr << "pcap_setdirection() on " << interface << " failed: "   
           << pcap_geterr(pcap_descriptor) << endl;
      return EXIT_FAILURE;
    }

    pcap_descriptors.push_back(pcap_descriptor);
    cout << "Opened " << interface << " for capture." << endl;
  }

  // Capture from each interface in a dedicated thread.
  vector<thread> threads;
  for (pcap_t* input : pcap_descriptors) {
    threads.push_back(thread([input, &pcap_descriptors]() {
      pcap_pkthdr packet_header;
      while (true) {
        // For each packet we receive on an interface, send it out all other
        // interfaces.
        const u_char* packet = pcap_next(input, &packet_header);
        if (packet == nullptr) {
          continue;
        }
        for (pcap_t* output : pcap_descriptors) {
          if (input != output) {
            pcap_sendpacket(output, packet, packet_header.caplen);
          }
        }
      }
    }));
  }
  for (thread& thread : threads) {
    thread.join();
  }
  return EXIT_SUCCESS;
}
