// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface   = flag.String("i", "eth0", "Interface to read packets from")
	fname   = flag.String("r", "", "Filename to read from, overrides -i")
	snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
	tstype  = flag.String("timestamp_type", "", "Type of timestamps to use")
	promisc = flag.Bool("promisc", true, "Set promiscuous mode")

	printer     = flag.Bool("print", true, "Print out packets, if false only prints out statistics")
	maxcount    = flag.Int("c", -1, "Only grab this many packets, then exit")
	decoder     = flag.String("decoder", "Ethernet", "Name of the decoder to use")
	dump        = flag.Bool("X", false, "If true, dump very verbose info on each packet")
	statsevery  = flag.Int("stats", 1000, "Output statistics every N packets")
	printErrors = flag.Bool("errors", false, "Print out packet dumps of decode errors, useful for checking decoders against live traffic")
	lazy        = flag.Bool("lazy", false, "If true, do lazy decoding")
	defrag      = flag.Bool("defrag", true, "If true, do IPv4 defrag")
)

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error
	go func() {
		for {
			http.Get("http://google.com")
			time.Sleep(2 * time.Second)
		}
	}()
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		// This is a little complicated because we want to allow all possible options
		// for creating the packet capture handle... instead of all this you can
		// just call pcap.OpenLive if you want a simple handle.
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatalf("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(*snaplen); err != nil {
			log.Fatalf("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatalf("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatalf("could not set timeout: %v", err)
		}
		if *tstype != "" {
			if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			} else if err := inactive.SetTimestampSource(t); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			}
		}
		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
	}
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}
	Run(handle)
}

func Run(src gopacket.PacketDataSource) {
	if !flag.Parsed() {
		log.Fatalln("Run called without flags.Parse() being called")
	}
	var dec gopacket.Decoder
	var ok bool
	if dec, ok = gopacket.DecodersByLayerName[*decoder]; !ok {
		log.Fatalln("No decoder named", *decoder)
	}
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = *lazy
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true
	fmt.Fprintln(os.Stderr, "Starting to read packets")
	count := 0
	bytes := int64(0)
	start := time.Now()
	errors := 0
	truncated := 0
	layertypes := map[gopacket.LayerType]int{}
	defragger := ip4defrag.NewIPv4Defragmenter()

	for packet := range source.Packets() {
		count++
		bytes += int64(len(packet.Data()))

		// defrag the IPv4 packet if required
		if *defrag {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer == nil {
				continue
			}
			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length

			newip4, err := defragger.DefragIPv4(ip4)
			if err != nil {
				log.Fatalln("Error while de-fragmenting", err)
			} else if newip4 == nil {
				continue // packet fragment, we don't have whole packet yet.
			}
			if newip4.Length != l {
				fmt.Printf("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					panic("Not a PacketBuilder")
				}
				nextDecoder := newip4.NextLayerType()
				nextDecoder.Decode(newip4.Payload, pb)
			}
		}

		if *dump {
			fmt.Println(packet.Dump())
			//fmt.Printf("%#v\n", hex.Dump(packet.Data()))
		} else if *printer {
			fmt.Println(packet)
			//fmt.Printf("%#v\n", hex.Dump(packet.Data()))
			fmt.Printf("%s\n\n", packet.Data())

		}
		if !*lazy || *printer || *dump { // if we've already decoded all layers...
			for _, layer := range packet.Layers() {
				layertypes[layer.LayerType()]++
			}
			if packet.Metadata().Truncated {
				truncated++
			}
			if errLayer := packet.ErrorLayer(); errLayer != nil {
				errors++
				if *printErrors {
					fmt.Println("Error:", errLayer.Error())
					fmt.Println("--- Packet ---")
					fmt.Println(packet.Dump())
				}
			}
		}
		done := *maxcount > 0 && count >= *maxcount
		if count%*statsevery == 0 || done {
			fmt.Fprintf(os.Stderr, "Processed %v packets (%v bytes) in %v, %v errors and %v truncated packets\n", count, bytes, time.Since(start), errors, truncated)
			if len(layertypes) > 0 {
				fmt.Fprintf(os.Stderr, "Layer types seen: %+v\n", layertypes)
			}
		}
		if done {
			break
		}
	}
}
