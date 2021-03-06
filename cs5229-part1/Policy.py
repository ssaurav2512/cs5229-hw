#!/usr/bin/python

"""
@Author Saurav Sircar/A0198873E
Date : 05/09/2019
"""


import httplib
import json
import time


class flowStat(object):
    def __init__(self, server):
        self.server = server

    def get(self, switch):
        ret = self.rest_call({}, 'GET', switch)
        return json.loads(ret[2])

    def rest_call(self, data, action, switch):
        path = '/wm/core/switch/'+switch+"/flow/json"
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        #print path
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        conn.close()
        return ret

class StaticFlowPusher(object):
    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, objtype, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticflowpusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        # print response
        ret = (response.status, response.reason, response.read())
        # print ret
        conn.close()
        return ret

pusher = StaticFlowPusher('127.0.0.1')
flowget = flowStat('127.0.0.1')

# To insert the policies for the traffic applicable to path between S1 and S2
def S1toS2():
    S1H2 = {"switch": "00:00:00:00:00:00:00:01",
            "name": "S1H2",
            "cookie": "0",
            "priority": "100",
            "in_port": "1",
            "eth_type": "0x800",
            "ipv4_src": "10.0.0.1",
            "ipv4_dst": "10.0.0.2",
            "active": "true",
            "actions": "set_queue=1,output=2"}

    S2H2 = {"switch":"00:00:00:00:00:00:00:02",
            "name":"S2H2",
            "cookie":"0",
            "priority":"100",
            "in_port":"2",
            "eth_type":"0x800",
            "ipv4_src":"10.0.0.1",
            "ipv4_dst":"10.0.0.2",
            "active":"true",
            "actions":"set_queue=1,output=1"}
    pusher.set(S1H2)
    pusher.set(S2H2)
    pass

# To insert the policies for the traffic applicable to path between S2 and S3
def S2toS3():
    S2H3_1 = {"switch":"00:00:00:00:00:00:00:02",
            "name":"S2H3_1",
            "cookie":"0",
            "priority":"1000",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x3e8/0xfff8",
            "ipv4_src":"10.0.0.2",
            "ipv4_dst":"10.0.0.3",
            "active":"true",
            "actions":""}
    S2H3_2 = {"switch":"00:00:00:00:00:00:00:02",
            "name":"S2H3_2",
            "cookie":"0",
            "priority":"500",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x3f0/0xfff0",
            "ipv4_src":"10.0.0.2",
            "ipv4_dst":"10.0.0.3",
            "active":"true",
            "actions":""}
    S2H3_3 = {"switch":"00:00:00:00:00:00:00:02",
            "name":"S2H3_3",
            "cookie":"0",
            "priority":"100",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x400/0xffc0",
            "ipv4_src":"10.0.0.2",
            "ipv4_dst":"10.0.0.3",
            "active":"true",
            "actions":""}
    S2H3_4 = {"switch":"00:00:00:00:00:00:00:02",
            "name":"S2H3_4",
            "cookie":"0",
            "priority":"1200",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x440/0xfff8",
            "ipv4_src":"10.0.0.2",
            "ipv4_dst":"10.0.0.3",
            "active":"true",
            "actions":""}
    S2H3_5 = {"switch":"00:00:00:00:00:00:00:02",
            "name":"S2H3_5",
            "cookie":"0",
            "priority":"1200",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x448/0xfffc",
            "ipv4_src":"10.0.0.2",
            "ipv4_dst":"10.0.0.3",
            "active":"true",
            "actions":""}
    S2H3_6 = {"switch":"00:00:00:00:00:00:00:02",
            "name":"S2H3_6",
            "cookie":"0",
            "priority":"1200",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x44c",
            "ipv4_src":"10.0.0.2",
            "ipv4_dst":"10.0.0.3",
            "active":"true",
            "actions":""}

    S3H2_1 = {"switch":"00:00:00:00:00:00:00:03",
            "name":"S3H2_1",
            "cookie":"0",
            "priority":"100",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x3e8/0xfff8",
            "ipv4_src":"10.0.0.3",
            "ipv4_dst":"10.0.0.2",
            "active":"true",
            "actions":""}
    S3H2_2 = {"switch":"00:00:00:00:00:00:00:03",
            "name":"S3H2_2",
            "cookie":"0",
            "priority":"100",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x3f0/0xfff0",
            "ipv4_src":"10.0.0.3",
            "ipv4_dst":"10.0.0.2",
            "active":"true",
            "actions":""}
    S3H2_3 = {"switch":"00:00:00:00:00:00:00:03",
            "name":"S3H2_3",
            "cookie":"0",
            "priority":"100",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x400/0xffc0",
            "ipv4_src":"10.0.0.3",
            "ipv4_dst":"10.0.0.2",
            "active":"true",
            "actions":""}
    S3H2_4 = {"switch":"00:00:00:00:00:00:00:03",
            "name":"S3H2_4",
            "cookie":"0",
            "priority":"100",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x440/0xfff8",
            "ipv4_src":"10.0.0.3",
            "ipv4_dst":"10.0.0.2",
            "active":"true",
            "actions":""}
    S3H2_5 = {"switch":"00:00:00:00:00:00:00:03",
            "name":"S3H2_5",
            "cookie":"0",
            "priority":"100",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x448/0xfffc",
            "ipv4_src":"10.0.0.3",
            "ipv4_dst":"10.0.0.2",
            "active":"true",
            "actions":""}
    S3H2_6 = {"switch":"00:00:00:00:00:00:00:03",
            "name":"S3H2_6",
            "cookie":"0",
            "priority":"100",
            "in_port":"1",
            "eth_type":"0x800",
            "ip_proto":"0x11",
            "udp_dst":"0x44c",
            "ipv4_src":"10.0.0.3",
            "ipv4_dst":"10.0.0.2",
            "active":"true",
            "actions":""}

    pusher.set(S2H3_1)
    pusher.set(S2H3_2)
    pusher.set(S2H3_3)
    pusher.set(S2H3_4)
    pusher.set(S2H3_5)
    pusher.set(S2H3_6)

    pusher.set(S3H2_1)
    pusher.set(S3H2_2)
    pusher.set(S3H2_3)
    pusher.set(S3H2_4)
    pusher.set(S3H2_5)
    pusher.set(S3H2_6)
    pass

# To insert the policies for the traffic applicable to path between S1 and S3
def S1toS3():
        # Policy to limit http traffic to 1 Mbps from S1
    S1H3_1MB = {"switch": "00:00:00:00:00:00:00:01",
                "name": "S1H3_1MB",
                "cookie": "0",
                "priority": "2",
                "in_port": "1",
                "eth_type": "0x800",
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.3",
                "ip_proto": "0x06",
                "tcp_dst": "80",
                "active": "true",
                "actions": "set_queue=1,output=3"}
    # Policy to limit http traffic to 512 Kbps from S3
    S3H3_1MB = {"switch": "00:00:00:00:00:00:00:03",
                "name": "S3H3_1MB",
                "cookie": "0",
                "priority": "2",
                "in_port": "2",
                "eth_type": "0x800",
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.3",
                "ip_proto": "0x06",
                "tcp_dst": "80",
                "active": "true",
                "actions": "set_queue=1,output=1"}

    # For switch S1, limit the traffic to 512Kbps for http
    S1H3_512KB = {"switch": "00:00:00:00:00:00:00:01",
                "name": "S1H3_512KB",
                "cookie": "0",
                "priority": "2",
                "in_port": "1",
                "eth_type": "0x800",
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.3",
                "ip_proto": "0x06",
                "tcp_dst": "80",
                "active": "true",
                "actions": "set_queue=2,output=3"}
    # For switch S3, limit the traffic to 512KMbps for http
    S3H3_512KB = {"switch": "00:00:00:00:00:00:00:03",
                "name": "S3H3_512KB",
                "cookie": "0",
                "priority": "2",
                "in_port": "2",
                "eth_type": "0x800",
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.3",
                "ip_proto": "0x06",
                "tcp_dst": "80",
                "active": "true",
                "actions": "set_queue=2,output=1"}

    pusher.set(S1H3_1MB)
    pusher.set(S3H3_1MB)

    limited = False  # Set to True when limited to 512Kbps, False when limite to 1Mbps
    current_limit = 0  # current limit that when bit count reaches to switch policy
    TenMB = 10 * 1024 * 1024
    TwentyMB = 2 * TenMB
    current_limit += TwentyMB
    while True:
        response = flowget.get("00:00:00:00:00:00:00:01")
        policy_count = len(response['flows'])
        for i in range(policy_count):
            policy = response['flows'][i]
            policy_match = policy['match']
            if 'eth_type' in policy_match and policy_match['eth_type'] == '0x0x800' and 'ip_proto' in policy_match \
                    and policy_match['ip_proto'] == '0x6' and 'tcp_dst' in policy_match and policy_match['tcp_dst'] == '80' \
                    and 'ipv4_src' in policy_match and policy_match['ipv4_src'] == '10.0.0.1' and 'ipv4_dst' in policy_match \
                    and policy_match['ipv4_dst'] == '10.0.0.3' and 'in_port' in policy_match and policy_match['in_port'] == '1':
                print "find matching policy"
                byte_count = policy['byteCount']
                bit_count = int(byte_count) * 8
                if bit_count > current_limit:
                    # if bit count is greater than current limit, we switch policy and increase the current_limit
                    if limited:
                        print "set to 1Mbps limit"
                        pusher.set(S1H3_1MB)
                        pusher.set(S3H3_1MB)
                        current_limit += TwentyMB
                    else:
                        print "set to 512Kbps limit"
                        pusher.set(S1H3_512KB)
                        pusher.set(S3H3_512KB)
                        current_limit += TenMB
                    limited = not limited
                    # since the traffic is rate limited, it needs 20 second to reach the next limit if it run in full
                    # speed, so we can sleep at least 20 second to do the next query. to play safe, we sleep 18 seconds
                    time.sleep(18)
                else:
                    # if bit count is less than current limit, we sleep to wait for more traffic. the time to sleep is
                    # calculated based on remaining bit and traffic speed. to play safe, we sleep 2 second less
                    print "wait for more traffic"
                    remaining = current_limit - bit_count
                    remaining_time = remaining / (512 * 1024)
                    if not limited:
                        remaining_time /= 2
                    if remaining_time - 2 > 0:
                        time.sleep(remaining_time - 2)
                break
            else:
                # if there is no matching policy found, we wait for 1 second to query again
                time.sleep(1)
    pass


def staticForwarding():
    # Below 4 flows are for setting up the static forwarding for the path H1->S1->S2->H2 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h1 and h2
    S1Staticflow1 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h1toh2","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=2"}
    S1Staticflow2 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h2toh1","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=1"}
    # Define static flow for Switch S2 for packet forwarding b/w h1 and h2
    S2Staticflow1 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h2toh1","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=2"}
    S2Staticflow2 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h1toh2","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=1"}

    # Below 4 flows are for setting up the static forwarding for the path H1->S1->S3->H3 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h1 and h3
    S1Staticflow3 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h1toh3","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=3"}
    S1Staticflow4 = {'switch':"00:00:00:00:00:00:00:01","name":"S1h3toh1","cookie":"0",
                    "priority":"1","in_port":"3","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=1"}
    # Define static flow for Switch S3 for packet forwarding b/w h1 and h3
    S3Staticflow1 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h3toh1","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.1","active":"true","actions":"output=2"}
    S3Staticflow2 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h1toh3","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.1",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=1"}

    # Below 4 flows are for setting up the static forwarding for the path H2->S2->S3->H3 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h2 and h3
    S2Staticflow3 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h2toh3","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=3"}
    S2Staticflow4 = {'switch':"00:00:00:00:00:00:00:02","name":"S2h3toh2","cookie":"0",
                    "priority":"1","in_port":"3","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=1"}
    # Define static flow for Switch S3 for packet forwarding b/w h2 and h3
    S3Staticflow3 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h3toh2","cookie":"0",
                    "priority":"1","in_port":"1","eth_type":"0x800","ipv4_src":"10.0.0.3",
                    "ipv4_dst":"10.0.0.2","active":"true","actions":"output=3"}
    S3Staticflow4 = {'switch':"00:00:00:00:00:00:00:03","name":"S3h2toh3","cookie":"0",
                    "priority":"1","in_port":"2","eth_type":"0x800","ipv4_src":"10.0.0.2",
                    "ipv4_dst":"10.0.0.3","active":"true","actions":"output=1"}

    #Now, Insert the flows to the switches
    pusher.set(S1Staticflow1)
    pusher.set(S1Staticflow2)
    pusher.set(S1Staticflow3)
    pusher.set(S1Staticflow4)

    pusher.set(S2Staticflow1)
    pusher.set(S2Staticflow2)
    pusher.set(S2Staticflow3)
    pusher.set(S2Staticflow4)

    pusher.set(S3Staticflow1)
    pusher.set(S3Staticflow2)
    pusher.set(S3Staticflow3)
    pusher.set(S3Staticflow4)


if __name__ =='__main__':
    staticForwarding()
    # S1toS2()
    # S2toS3()
    S1toS3()
    pass
