package main

import (
  "fmt"
  "log"
  "time"
  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

func devicePicker() string {
    devices, err := pcap.FindAllDevs()
    if err != nil {
      log.Fatal(err)
    }

    fmt.Println("Pick a device to scan on:")
    for n, device := range devices {
      fmt.Printf("\nNumber: %d :: ", n)
      fmt.Println("Name: ", device.Name)
      fmt.Println("Description: ", device.Description)
      for _, address := range device.Addresses {
        fmt.Printf("IP address: %s", address.IP)
        fmt.Printf(" :: ")
        fmt.Println("Subnet mask: %s", address.Netmask)
      }
    }

    var choice int
    fmt.Printf("Enter device number: ")
    fmt.Scanln(&choice)

    return devices[choice].Name
}

func main() {
  device := devicePicker()

  var timeout time.Duration = -1*time.Second
  handle, err := pcap.OpenLive(
    device,
    int32(65535),
    false,
    timeout,
  )
  if err != nil {log.Fatal(err)}
  defer handle.Close()

  handle.SetBPFFilter("arp")

  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range packetSource.Packets() {
    fmt.Println(packet)
  }
}
