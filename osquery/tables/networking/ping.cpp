/**
 * Copyright (c) 2021-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Including standard C, C++, network/socket related headers
// in additon to the osquery headers
#include <arpa/inet.h>
#include <boost/numeric/conversion/cast.hpp>
#include <chrono>
#include <ctype.h>
#include <iostream>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>
#include <osquery/core/tables.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define PING_PACKET_SIZE 64
#define MAX_PACKET_SIZE 65535

namespace osquery {
namespace tables {

uint16_t checksum(uint16_t *addr, unsigned len);

/* 
  The ping() function is mostly derived from versions from Mike Muuss and 
  https://gist.github.com/KelviNosse:
  Using socket sendto() to send the ping packet to the destination,
  and using select() to wait for the response.
  I followed their approach because this is what Linux ping does.
  One subtle detail is the use of static sckt (socket variable) to
  reuse the same socket when ping() is called repeatedly.
*/
uint64_t ping(std::string target)
{
  static int sckt = -1;
  static int retry = 1;
  //static int ntransmitted = 0; // sequence # for outbound packets 
  int sendLen;
  int recvfromLen;
  int fromLen;
  int ipHdrLen;
  int selectRet;
  uint64_t latency;
  struct hostent *hostentPtr;
  struct sockaddr_in to, from;
  u_char recvPacket[MAX_PACKET_SIZE];
  u_char pingPacket[PING_PACKET_SIZE];
  char hostnameBuf[MAXHOSTNAMELEN];
  std::string hostname;
  struct icmp *icmpPtr;
  fd_set rfds;
  struct timeval tv;
  struct timeval start, end;
  bool selecting = true;

  to.sin_family = AF_INET;

  to.sin_addr.s_addr = inet_addr(target.c_str());

  if (to.sin_addr.s_addr != (u_int)-1)
    hostname = target;
  else {
    hostentPtr = gethostbyname(target.c_str());
    if (!hostentPtr) {
      LOG(WARNING) << "unknown host "<< target << std::endl;
      return -1;
    }
    to.sin_family = hostentPtr->h_addrtype;
    bcopy(hostentPtr->h_addr, (caddr_t)&to.sin_addr, hostentPtr->h_length);
    strncpy(hostnameBuf, hostentPtr->h_name, sizeof(hostnameBuf) - 1);
    hostname = hostnameBuf;
  }

  // When ping() is called the first time, make the socket in sckt.
  // Subsequent times reuse the socket sckt.
  if (sckt == -1)
    if ( (sckt = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
      return -1; /* Needs to run as superuser!! */
    }

  icmpPtr = (struct icmp *)pingPacket;
  icmpPtr->icmp_type = ICMP_ECHO;
  icmpPtr->icmp_code = 0;
  icmpPtr->icmp_seq = 12345;
  icmpPtr->icmp_id = getpid();
  icmpPtr->icmp_cksum = checksum((unsigned short *)icmpPtr,PING_PACKET_SIZE);

  gettimeofday(&start, NULL);

  // Sending the ping packet to the destination
  sendLen = sendto(sckt, (char *)pingPacket, PING_PACKET_SIZE, 0, (struct sockaddr*)&to, (socklen_t)sizeof(struct sockaddr_in));

  if (sendLen < 0 || sendLen != PING_PACKET_SIZE) {
    if (sendLen < 0)
      perror("sendto error");
    LOG(WARNING) << "wrote " << hostname << " " <<  PING_PACKET_SIZE << " chars, ret= " << sendLen << std::endl;
  }
  
  // Setting up select() parameters
  FD_ZERO(&rfds);
  FD_SET(sckt, &rfds);
  tv.tv_sec = 1;
  tv.tv_usec = 0;

  // Loop for select() 
  while (selecting) {
    selectRet = select(sckt+1, &rfds, NULL, NULL, &tv);

    if (selectRet == -1) {
      perror("select()");
      return -1;
    }
    else if (selectRet) {
      fromLen = sizeof(sockaddr_in);
      if ( (recvfromLen = recvfrom(sckt, (char *)recvPacket, MAX_PACKET_SIZE, 0, (struct sockaddr *)&from, (socklen_t*)&fromLen)) < 0) {
        perror("recvfrom error");
        return -1;
      }

      // Check the IP header
      //ipPtr = (struct ip *)((char*)recvPacket); 
      ipHdrLen = sizeof( struct ip ); 
      if (recvfromLen < (ipHdrLen + ICMP_MINLEN)) { 
        LOG(WARNING) << "packet too short (" << recvfromLen  << " bytes) from " << hostname << std::endl;;
        return -1; 
      } 

      // Now the ICMP part 
      icmpPtr = (struct icmp *)(recvPacket + ipHdrLen); 
      if (icmpPtr->icmp_type == ICMP_ECHOREPLY) {
        if (icmpPtr->icmp_seq != 12345) {
          LOG(WARNING) << "received sequence # " << icmpPtr->icmp_seq << std::endl;
          continue;
        }
        if (icmpPtr->icmp_id != getpid()) {
          LOG(WARNING) << "received id " << icmpPtr->icmp_id << std::endl;
          continue;
        }
        selecting = false;
      }
      else {
        LOG(WARNING) << "Recv: not an echo reply" << std::endl;
        continue;
      }
  
      gettimeofday(&end, NULL);

      // Converting to useconds from time difference
      latency = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
      
      retry = 1;
      return latency;
    }
    else {
      // Let ping() try once more before giving warning
      if (retry == 0) {
        LOG(WARNING) << "No data within one seconds.\n";
        retry = 1;
      } else
        retry--;
      return 0;
    }
  }
  return 0;
}

// Very common checksum function
uint16_t checksum(uint16_t *addr, unsigned len)
{  
  uint32_t sum=0;
  uint16_t result;
  
  for ( sum = 0; len > 1; len -= 2 )
    sum += *addr++;
  if ( len == 1 )
    sum += *(unsigned char*)addr;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

/*
   Interface function named in specs/ping.table
*/
QueryData genPing(QueryContext& context) {
  QueryData results;
  char latencyStr[64];
  int lastIdx;

  auto requests = context.constraints["host"].getAll(EQUALS);

  // Using the like clause for host wouldn't make sense
  if (context.constraints["host"].getAll(LIKE).size()) {
    LOG(WARNING) << "Using LIKE clause for host is not supported";
  }

  for (const auto& request : requests) {
    Row r;
    r["host"] = request;
    uint64_t latency = 0;
    for (int i=0; i<10; i++) {
      latency = ping(r["host"]);
      if (latency > 0)
        break;
    }

    sprintf(latencyStr,"%ld.%d", latency/1000, (int)(latency%1000));
    lastIdx = strlen(latencyStr) - 1;
    while (latencyStr[lastIdx] == '0') {
      latencyStr[lastIdx] = '\0';
      lastIdx--;
    }
    if (latencyStr[lastIdx] == '.')
      latencyStr[lastIdx] = '\0';

    r["latency"] = latencyStr;
    results.push_back(r);
    sleep(1);
  }
  return results;
}
} // namespace tables
} // namespace osquery
