// -- BEGIN LICENSE BLOCK ----------------------------------------------
/*!
*  Copyright (C) 2023, SICK AG, Waldkirch, Germany
*  Copyright (C) 2023, FZI Forschungszentrum Informatik, Karlsruhe, Germany
*
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.

*/
// -- END LICENSE BLOCK ------------------------------------------------

#if (_MSC_VER >= 1700)

#  include <memory>
#  include <sstream>
#include <iso646.h> 

#  include <chrono>
#  include <random>
#  include <string>

// TinyXML-2 XML DOM parser
#  include "sick_safevisionary_base/tinyxml2.h"

#  include "sick_safevisionary_base/UdpSocket.h"
#  include "sick_safevisionary_base/VisionaryAutoIPScan.h"

namespace visionary {

VisionaryAutoIPScan::VisionaryAutoIPScan() {}

VisionaryAutoIPScan::~VisionaryAutoIPScan() {}

/*
std::vector<VisionaryAutoIPScan::DeviceInfo>
VisionaryAutoIPScan::doScan(int timeOut, const std::string& broadcastAddress, uint16_t port)
{
  // Init Random generator
  std::random_device rd;
  std::default_random_engine mt(rd());
  unsigned int teleIdCounter = mt();
  std::vector<VisionaryAutoIPScan::DeviceInfo> deviceList;

  std::unique_ptr<UdpSocket> pTransport(new UdpSocket());

  if (pTransport->connect(broadcastAddress, htons(port)) != 0)
  {
    return deviceList;
  }

  // AutoIP Discover Packet
  std::vector<uint8_t> autoIpPacket;
  autoIpPacket.push_back(0x10); // CMD
  autoIpPacket.push_back(0x0);  // reserved
  // length of datablock
  autoIpPacket.push_back(0x0);
  autoIpPacket.push_back(0x0);
  // Mac address
  autoIpPacket.push_back(0xFF);
  autoIpPacket.push_back(0xFF);
  autoIpPacket.push_back(0xFF);
  autoIpPacket.push_back(0xFF);
  autoIpPacket.push_back(0xFF);
  autoIpPacket.push_back(0xFF);
  // telgram id
  autoIpPacket.push_back(0x0);
  autoIpPacket.push_back(0x0);
  autoIpPacket.push_back(0x0);
  autoIpPacket.push_back(0x0);
  // reserved
  autoIpPacket.push_back(0x0);
  autoIpPacket.push_back(0x0);

  // Replace telegram id in packet
  unsigned int curtelegramID = teleIdCounter++;
  memcpy(&autoIpPacket.data()[10], &curtelegramID, 4u);

  // Send Packet
  pTransport->send(autoIpPacket);

  // Check for answers to Discover Packet
  const std::chrono::steady_clock::time_point startTime(std::chrono::steady_clock::now());
  while (true)
  {
    std::vector<std::uint8_t> receiveBuffer;
    const std::chrono::steady_clock::time_point now(std::chrono::steady_clock::now());
    if ((now - startTime) > std::chrono::milliseconds(timeOut))
    {
      break;
    }
    if (pTransport->recv(receiveBuffer, 1400) > 16) // 16 bytes minsize
    {
      unsigned int pos = 0;
      if (receiveBuffer[pos++] != 0x90) // 0x90 = answer package id and 16 bytes minsize
      {
        continue;
      }
      pos += 1; // unused byte
      unsigned int payLoadSize = receiveBuffer[pos] << 8 | receiveBuffer[pos + 1];
      pos += 2;
      pos += 6; // Skip mac address(part of xml)
      unsigned int recvTelegramID = receiveBuffer[pos] | receiveBuffer[pos + 1] << 8 |
                                    receiveBuffer[pos + 2] << 16 | receiveBuffer[pos + 3] << 24;
      pos += 4;
      // check if it is a response to our scan
      if (recvTelegramID != curtelegramID)
      {
        continue;
      }
      pos += 2; // unused
      // Get XML Payload
      char xmlPayload[1400];
      memset(xmlPayload, 0, sizeof(xmlPayload));
      memcpy(&xmlPayload, &receiveBuffer[pos], payLoadSize);
      std::stringstream stringStream(xmlPayload);
      try
      {
        std::optional<DeviceInfo> dI = parseAutoIPXml(stringStream);
        if (dI.has_value())
        {
          deviceList.push_back(dI.value());
        }
      }
      catch (...)
      {
      }
    }
  }
  return deviceList;
}
*/

/*
std::optional <VisionaryAutoIPScan::DeviceInfo>
VisionaryAutoIPScan::parseAutoIPXml(std::stringstream& rStringStream)
{
  // Parse XML string into DOM
  tinyxml2::XMLDocument tree;
  //auto tXMLError = tree.Parse(rStringStream.str()); //Buggy, CE fixed below.
  auto tXMLError = tree.Parse(rStringStream.str().c_str());
  if (tXMLError != tinyxml2::XMLError::XML_SUCCESS)
  {
    std::printf("Reading XML tree in AutoIP NetScan result failed.");
    //return false; //Buggy, CE fixed below
    return DeviceInfo();
  }

  DeviceInfo dI;
  dI.DeviceName = "";
  dI.IpAddress  = "";
  dI.MacAddress = "";
  dI.Port       = "";
  dI.SubNet     = "";

  //tinyxml2::XMLNode const* const ptDataSetsTree = tree.FirstChildElement("NetScanResult"); //Buggy, CE fixed below.
  auto* pElement = tree.FirstChildElement("NetScanResult");
  //if (ptDataSetsTree != 0) //Buggy, CE fixed below.
  if (pElement)
  {
    // Query XML attributes
    //tinyxml2::XMLAttribute const* ptAttr = 0;

    //ptAttr = ptDataSetsTree->FindAttribute("DeviceType"); //Buggy, CE fixed below
    tinyxml2::XMLAttribute const* ptAttrDevType = pElement->FindAttribute("DeviceType");
    //if (ptAttr != 0) //Buggy, CE fixed below
    if (ptAttrDevType)
    {
      dI.DeviceName = ptAttrDevType->Value();
    }

    //ptAttr = ptDataSetsTree->FindAttribute("IPAddress");
    tinyxml2::XMLAttribute const* ptAttrIPAdd = pElement->FindAttribute("IPAddress");
    if (ptAttrIPAdd)
    {
      dI.IpAddress = ptAttrIPAdd->Value();
    }

    //ptAttr = ptDataSetsTree->FindAttribute("MACAddr");
    tinyxml2::XMLAttribute const* ptAttrMACAdd = pElement->FindAttribute("MACAddr");
    if (ptAttrMACAdd)
    {
      dI.MacAddress = ptAttrMACAdd->Value();
    }

    //ptAttr = ptDataSetsTree->FindAttribute("HostPortNo");
    tinyxml2::XMLAttribute const* ptAttrHostPortNo = pElement->FindAttribute("HostPortNo");
    if (ptAttrHostPortNo)
    {
      dI.Port = ptAttrHostPortNo->Value();
    }

    //ptAttr = ptDataSetsTree->FindAttribute("IPMask");
    tinyxml2::XMLAttribute const* ptAttrIPMask = pElement->FindAttribute("IPMask");
    if (ptAttrIPMask)
    {
      dI.SubNet = ptAttrIPMask->Value();
    }
  }

  return dI;
}
*/
} // namespace visionary
#endif
