# collector.py
# Chức năng: Thu thập ARP traffic (dataset) + forwarding để Mininet thông mạng
# - Ghi ARP vào CSV (benign/attack)
# - Duy trì forwarding dạng hub (FLOOD) để đảm bảo ARP/PING hoạt động trong lab

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib.packet import ether_types
import time, os, csv

ZERO_MAC = "00:00:00:00:00:00"


def ip_last_octet(ip: str) -> int:
    try:
        return int(ip.split(".")[-1])
    except Exception:
        return -1


def mac_last_byte(mac: str) -> int:
    try:
        return int(mac.split(":")[-1], 16)
    except Exception:
        return -1


class ARPCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ===== Dataset output + labeling =====
        self.out_csv = os.environ.get("DATA_OUT", "arp_dataset.csv")
        self.default_label = os.environ.get("DATA_LABEL", "benign").strip().lower()
        self.label_file = os.environ.get("DATA_LABEL_FILE", "label.txt")
        self.label = self.default_label
        self.warmstart = os.environ.get("DATA_WARMSTART", "0") == "1"

        # ===== Feature state =====
        # rate counter per (dpid, src_ip) in 1s window
        self.counts = {}
        self.win_start = {}

        # mac change counter per src_ip
        self.last_mac_for_ip = {}
        self.mac_change_count = {}

        # Warm-start: nạp trạng thái last_mac/mac_change_count từ CSV cũ (nếu muốn)
        if self.warmstart and os.path.exists(self.out_csv):
            try:
                with open(self.out_csv, "r", newline="") as rf:
                    reader = csv.DictReader(rf)
                    for row in reader:
                        src_ip = row.get("src_ip")
                        src_mac = row.get("src_mac")
                        if not src_ip or not src_mac:
                            continue
                        self.last_mac_for_ip[src_ip] = src_mac
                        try:
                            self.mac_change_count[src_ip] = int(row.get("mac_change_count", 0))
                        except Exception:
                            pass
                self.logger.info(f"[COLLECTOR] Warm-start loaded state from {self.out_csv}")
            except Exception as e:
                self.logger.warning(f"[COLLECTOR] Warm-start failed: {e}")

        # CSV writer
        new_file = not os.path.exists(self.out_csv)
        self.f = open(self.out_csv, "a", newline="")
        self.w = csv.writer(self.f)
        if new_file:
            self.w.writerow([
                "ts", "dpid", "opcode",
                "src_ip", "dst_ip", "src_mac", "dst_mac",
                "src_ip_oct", "dst_ip_oct", "src_mac_b", "dst_mac_b",
                "is_request", "is_reply", "is_gratuitous", "dst_mac_zero",
                "req_rate_1s", "mac_change_count", "label"
            ])

        self.logger.info(
            f"[COLLECTOR] Output={self.out_csv} | DefaultLabel={self.default_label} | LabelFile={self.label_file}"
        )

    def _refresh_label(self):
        """Đọc nhãn từ file label.txt (nếu có) để đổi benign/attack không cần restart."""
        try:
            if self.label_file and os.path.exists(self.label_file):
                with open(self.label_file, "r") as lf:
                    lbl = (lf.read() or "").strip().lower()
                    if lbl:
                        self.label = lbl
                        return
        except Exception:
            pass
        self.label = self.default_label

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss: gửi packet lên controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst))
        self.logger.info(f"[COLLECTOR] Switch {dp.id} connected. Table-miss installed.")

    def _update_rate(self, dpid, src_ip) -> int:
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

    def _update_mac_change(self, src_ip, src_mac) -> int:
        if src_ip not in self.last_mac_for_ip:
            self.last_mac_for_ip[src_ip] = src_mac
            self.mac_change_count[src_ip] = 0
            return 0

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
        in_port = msg.match.get('in_port')
        dpid = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # Bỏ qua LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # ===== GHI DATASET (chỉ ARP) =====
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            a = pkt.get_protocol(arp.arp)
            if a is not None:
                # Cho phép đổi nhãn động bằng label.txt
                self._refresh_label()

                ts = time.time()
                src_ip, dst_ip = a.src_ip, a.dst_ip
                src_mac = eth.src
                dst_mac = getattr(a, 'dst_mac', eth.dst)

                # Chỉ đếm flooding với ARP REQUEST
                req_rate = self._update_rate(dpid, src_ip) if a.opcode == arp.ARP_REQUEST else 0
                mac_chg = self._update_mac_change(src_ip, src_mac)

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

        # ===== FORWARDING (để lab thông mạng) =====
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)
