# collector.py - PHIÊN BẢN ĐÃ SỬA LỖI FORWARDING
# Chức năng: Vừa ghi log ARP vào CSV, vừa chuyển mạch để mạng thông (Ping được)
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib.packet import ether_types
import time, os, csv

ZERO_MAC = "00:00:00:00:00:00"

def ip_last_octet(ip: str) -> int:
    try: return int(ip.split(".")[-1])
    except: return -1

def mac_last_byte(mac: str) -> int:
    try: return int(mac.split(":")[-1], 16)
    except: return -1

class ARPCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Lấy nhãn dữ liệu từ biến môi trường (mặc định là benign)
        self.label = os.environ.get("DATA_LABEL", "benign")
        self.out_csv = os.environ.get("DATA_OUT", "arp_dataset.csv")

        # Các biến đếm để trích xuất đặc trưng (Features)
        self.counts = {}
        self.win_start = {}
        self.last_mac_for_ip = {}
        self.mac_change_count = {}

        # Tạo file CSV và viết Header nếu file chưa tồn tại
        new_file = not os.path.exists(self.out_csv)
        self.f = open(self.out_csv, "a", newline="")
        self.w = csv.writer(self.f)
        if new_file:
            self.w.writerow([
                "ts","dpid","opcode",
                "src_ip","dst_ip","src_mac","dst_mac",
                "src_ip_oct","dst_ip_oct","src_mac_b","dst_mac_b",
                "is_request","is_reply","is_gratuitous","dst_mac_zero",
                "req_rate_1s","mac_change_count","label"
            ])
        self.logger.info(f"[COLLECTOR] Running... Output={self.out_csv}, Label={self.label}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        # Cài flow mặc định: Gửi mọi gói tin lạ lên Controller
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match,
                                      instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]))
        self.logger.info(f"Switch {dp.id} connected. Forwarding enabled.")

    def _update_rate(self, dpid, src_ip):
        now = time.time()
        self.counts.setdefault(dpid, {})
        self.win_start.setdefault(dpid, {})
        if src_ip not in self.counts[dpid]:
            self.counts[dpid][src_ip] = 0
            self.win_start[dpid][src_ip] = now
        if now - self.win_start[dpid][src_ip] > 1.0:
            self.counts[dpid][src_ip] = 0
            self.win_start[dpid][src_ip] = now
        self.counts[dpid][src_ip] += 1
        return self.counts[dpid][src_ip]

    def _update_mac_change(self, src_ip, src_mac):
        if src_ip not in self.last_mac_for_ip:
            self.last_mac_for_ip[src_ip] = src_mac
            self.mac_change_count[src_ip] = 0
        else:
            if self.last_mac_for_ip[src_ip] != src_mac:
                self.mac_change_count[src_ip] = self.mac_change_count.get(src_ip, 0) + 1
                self.last_mac_for_ip[src_ip] = src_mac
        return self.mac_change_count.get(src_ip, 0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        dpid = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Bỏ qua gói tin LLDP (Link Layer Discovery Protocol)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # --- PHẦN 1: GHI LOG (Chỉ dành cho gói ARP) ---
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            a = pkt.get_protocol(arp.arp)
            if a:
                ts = time.time()
                src_ip, dst_ip = a.src_ip, a.dst_ip
                src_mac, dst_mac = eth.src, a.dst_mac

                req_rate = self._update_rate(dpid, src_ip) if a.opcode == arp.ARP_REQUEST else 0
                mac_chg = self._update_mac_change(src_ip, src_mac)

                # Ghi vào CSV
                self.w.writerow([
                    ts, dpid, int(a.opcode),
                    src_ip, dst_ip, src_mac, dst_mac,
                    ip_last_octet(src_ip), ip_last_octet(dst_ip),
                    mac_last_byte(src_mac), mac_last_byte(dst_mac),
                    1 if a.opcode == arp.ARP_REQUEST else 0,
                    1 if a.opcode == arp.ARP_REPLY else 0,
                    1 if src_ip == dst_ip else 0,
                    1 if dst_mac == ZERO_MAC else 0,
                    req_rate, mac_chg, self.label
                ])
                self.f.flush()

        # --- PHẦN 2: CHUYỂN MẠCH (QUAN TRỌNG: ĐỂ PING ĐƯỢC) ---
        # Flood (Gửi ra mọi cổng) để đảm bảo gói tin đi đến đích
        # Đây là hành động của Hub/Switch đơn giản
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)