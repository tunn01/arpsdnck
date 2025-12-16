# Tên file: paper_firewall.py
# Mô tả: Firewall chống ARP Spoofing và Flooding bám sát Algorithm 1 (Telematics 2024)
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib.packet import ether_types
import time


ZERO_MAC = "00:00:00:00:00:00"


class PaperBasedFirewall(app_manager.RyuApp):
    """
    Algorithm 1 (ARP Spoofing Detection Algorithm) – paper 2024
    Input: ARP Request packet P
    Checks:
      - Dest IP in cache? MAC mismatch with source MAC => spoof alert
      - Src  IP in cache? MAC mismatch with source MAC => spoof alert
      - Number of ARP requests from same IP exceeds threshold => flooding alert
    Mitigation: install DROP flow for attacker MAC
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PaperBasedFirewall, self).__init__(*args, **kwargs)

        # Threshold paper gợi ý 50; demo giảm xuống 20 cho dễ test
        self.ARP_THRESHOLD = 20

        # ARP_Cache: { ip -> mac }
        self.arp_cache = {}

        # Rate limit per-switch per-source-ip (chỉ đếm ARP REQUEST)
        self.packet_counts = {}   # {dpid: {src_ip: count}}
        self.start_time = {}      # {dpid: {src_ip: window_start}}

        # L2 learning để ping/traffic thường chạy được (không liên quan Algorithm 1 nhưng cần để lab hoạt động)
        self.mac_to_port = {}     # {dpid: {mac: port}}

    # ------------------- OpenFlow helpers -------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss: gửi packet lên controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Switch connected. Table-miss flow installed.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority, match=match,
                      instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def _install_drop_src_mac(self, datapath, mac_block):
        """Mitigation: DROP vĩnh viễn theo eth_src (paper: mitigate at switch)."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=mac_block)

        # instructions rỗng => DROP
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=[])
        datapath.send_msg(mod)
        self.logger.warning(f"[MITIGATION] Installed DROP flow for attacker MAC: {mac_block}")

    # ------------------- Algorithm 1 core -------------------
    def _rate_limit_arp_requests(self, dpid, src_ip):
        """
        Algorithm 1 line 17-19:
        Count ARP REQUESTs from same IP in a sliding window (1s).
        Return True if SAFE, False if EXCEEDS threshold.
        """
        now = time.time()

        if dpid not in self.packet_counts:
            self.packet_counts[dpid] = {}
            self.start_time[dpid] = {}

        if src_ip not in self.packet_counts[dpid]:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now

        # reset window mỗi 1 giây
        if now - self.start_time[dpid][src_ip] > 1.0:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now

        self.packet_counts[dpid][src_ip] += 1
        return self.packet_counts[dpid][src_ip] <= self.ARP_THRESHOLD

    def _algo1_check_and_learn(self, src_ip, src_mac, dst_ip, dst_mac):
        """
        Bám sát Algorithm 1:
        - Check destination IP in cache (line 3-9)
        - Check source IP in cache      (line 10-16)
        Return: (is_spoofing: bool, reason: str)
        """
        # --- Line 3-9: Destination IP in P in ARP_Cache? ---
        if dst_ip in self.arp_cache:
            if self.arp_cache[dst_ip] != src_mac:
                return True, f"DEST mismatch: cache[{dst_ip}]={self.arp_cache[dst_ip]} != src_mac={src_mac}"
        else:
            # NOTE: Trong ARP Request, dst_mac thường là 00:00:00:00:00:00.
            # Paper line 8 vẫn nói “add Destination IP and MAC from P”, nên ta làm đúng
            # nhưng chỉ học nếu dst_mac != ZERO_MAC để tránh “học rác”.
            if dst_mac and dst_mac != ZERO_MAC:
                self.arp_cache[dst_ip] = dst_mac
                self.logger.info(f"[LEARN] Added DEST mapping {dst_ip} -> {dst_mac}")

        # --- Line 10-16: Source IP in P in ARP_Cache? ---
        if src_ip in self.arp_cache:
            if self.arp_cache[src_ip] != src_mac:
                return True, f"SRC mismatch: cache[{src_ip}]={self.arp_cache[src_ip]} != src_mac={src_mac}"
        else:
            self.arp_cache[src_ip] = src_mac
            self.logger.info(f"[LEARN] Added SRC mapping {src_ip} -> {src_mac}")

        return False, ""

    # ------------------- Packet processing -------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Init L2 table
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # ================== ARP handling (Algorithm 1 input is ARP REQUEST) ==================
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt is None:
                return

            # Paper Algorithm 1: input is ARP Request Packet P
            # -> only apply detection on opcode=ARP_REQUEST
            if arp_pkt.opcode == arp.ARP_REQUEST:
                src_ip = arp_pkt.src_ip
                src_mac = eth.src
                dst_ip = arp_pkt.dst_ip
                dst_mac = arp_pkt.dst_mac  # often 00..00 in request

                # Line 17-19: flooding check (ARP REQUEST only)
                if not self._rate_limit_arp_requests(dpid, src_ip):
                    self.logger.warning(f"[ALGO1-FLOODING] src_ip={src_ip} exceeded threshold={self.ARP_THRESHOLD}. BLOCK mac={src_mac}")
                    self._install_drop_src_mac(datapath, src_mac)
                    return  # drop

                # Line 3-16: spoofing check for DEST + SRC
                is_spoof, reason = self._algo1_check_and_learn(src_ip, src_mac, dst_ip, dst_mac)
                if is_spoof:
                    self.logger.warning(f"[ALGO1-SPOOFING] {reason}. BLOCK mac={src_mac} (src_ip={src_ip}, dst_ip={dst_ip})")
                    self._install_drop_src_mac(datapath, src_mac)
                    return  # drop

            # Nếu ARP an toàn (hoặc là ARP reply), vẫn flood để ARP hoạt động bình thường
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return

        # ================== Non-ARP traffic: L2 forwarding so lab works ==================
        dst = eth.dst
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Optional: install flow to reduce packet-in (learning switch behavior)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=60)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)


// GIẢI THÍCH CODE TRÍCH DẪN TỪ TÀI LIỆU PHẦN THUẬT TOÁN
# Tên file: arp_firewall.py
# Mô tả: Firewall chống ARP Spoofing và Flooding bám sát Algorithm 1 (Telematics 2024)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib.packet import ether_types
import time

ZERO_MAC = "00:00:00:00:00:00"


class PaperBasedFirewall(app_manager.RyuApp):
    """
    Mapping với Algorithm 1 (Telematics 2024):
      - Line 3–9 : Check DEST IP in ARP cache + learn DEST mapping
      - Line 10–16: Check SRC  IP in ARP cache + learn SRC mapping
      - Line 17–19: Detect ARP Flooding by thresholding request rate
    Mitigation: install DROP flow for attacker MAC (offload xuống switch)
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PaperBasedFirewall, self).__init__(*args, **kwargs)

        # Paper code fragment minh họa threshold=50; nhóm giảm xuống 20 để phù hợp lab/topo nhỏ và dễ test
        self.ARP_THRESHOLD = 20

        # ARP_Cache: { ip -> mac }  (dùng cho Algorithm 1 line 3–16)
        self.arp_cache = {}

        # Rate limit per-switch per-source-ip (chỉ đếm ARP REQUEST) (Algorithm 1 line 17–19)
        self.packet_counts = {}   # {dpid: {src_ip: count}}
        self.start_time = {}      # {dpid: {src_ip: window_start}}

        # L2 learning để traffic thường chạy được (ngoài Algorithm 1, nhưng cần cho thực nghiệm)
        self.mac_to_port = {}     # {dpid: {mac: port}}

    # ------------------- OpenFlow helpers -------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss: gửi packet lên controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Switch connected. Table-miss flow installed.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority, match=match,
                      instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def _install_drop_src_mac(self, datapath, mac_block):
        """Mitigation (offload xuống switch): DROP theo eth_src = MAC attacker."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=mac_block)

        # instructions rỗng => DROP
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=[])
        datapath.send_msg(mod)
        self.logger.warning(f"[MITIGATION] Installed DROP flow for attacker MAC: {mac_block}")

    # ------------------- Algorithm 1 core -------------------
    def _rate_limit_arp_requests(self, dpid, src_ip):
        """
        Algorithm 1 line 17–19:
        - "if Number of ARP Requests from Same IP Exceeds Threshold then Alert: Possible ARP Flooding"
        Cách hiện thực:
        - sliding window 1 giây cho mỗi (dpid, src_ip)
        - trả về True nếu <= threshold, False nếu vượt threshold
        """
        now = time.time()

        if dpid not in self.packet_counts:
            self.packet_counts[dpid] = {}
            self.start_time[dpid] = {}

        if src_ip not in self.packet_counts[dpid]:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now

        # reset window mỗi 1 giây
        if now - self.start_time[dpid][src_ip] > 1.0:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now

        self.packet_counts[dpid][src_ip] += 1
        return self.packet_counts[dpid][src_ip] <= self.ARP_THRESHOLD

    def _algo1_check_and_learn(self, src_ip, src_mac, dst_ip, dst_mac):
        """
        Algorithm 1:
        - Line 3–9  : DEST IP check + learn DEST mapping
        - Line 10–16: SRC  IP check + learn SRC mapping
        Return: (is_spoofing: bool, reason: str)
        """

        # ---------------- Line 3–9 (DESTINATION check) ----------------
        if dst_ip in self.arp_cache:
            # Line 4–6: nếu MAC trong cache khác src_mac trong gói P => spoof alert
            if self.arp_cache[dst_ip] != src_mac:
                return True, f"DEST mismatch: cache[{dst_ip}]={self.arp_cache[dst_ip]} != src_mac={src_mac}"
        else:
            # Line 8–9: add Destination IP and MAC from P to ARP cache
            # Lưu ý thực nghiệm: ARP Request thường có dst_mac = 00..00, nếu học bừa sẽ “học rác”
            if dst_mac and dst_mac != ZERO_MAC:
                self.arp_cache[dst_ip] = dst_mac
                self.logger.info(f"[LEARN] Added DEST mapping {dst_ip} -> {dst_mac}")

        # ---------------- Line 10–16 (SOURCE check) ----------------
        if src_ip in self.arp_cache:
            # Line 11–13: nếu MAC trong cache khác src_mac hiện tại => spoof alert
            if self.arp_cache[src_ip] != src_mac:
                return True, f"SRC mismatch: cache[{src_ip}]={self.arp_cache[src_ip]} != src_mac={src_mac}"
        else:
            # Line 15–16: add Source IP and MAC from P to ARP cache
            self.arp_cache[src_ip] = src_mac
            self.logger.info(f"[LEARN] Added SRC mapping {src_ip} -> {src_mac}")

        return False, ""

    # ------------------- Packet processing -------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # L2 learning table (để traffic thường chạy được)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # ================== ARP handling (Algorithm 1 input: ARP REQUEST) ==================
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt is None:
                return

            # Algorithm 1: Input là ARP Request Packet P
            # => chỉ áp dụng detection cho opcode = ARP_REQUEST
            if arp_pkt.opcode == arp.ARP_REQUEST:
                src_ip = arp_pkt.src_ip
                src_mac = eth.src
                dst_ip = arp_pkt.dst_ip
                dst_mac = arp_pkt.dst_mac  # thường là 00..00 trong ARP Request

                # ---------- Algorithm 1 line 17–19: Flooding check ----------
                if not self._rate_limit_arp_requests(dpid, src_ip):
                    self.logger.warning(
                        f"[ALGO1-FLOODING] src_ip={src_ip} exceeded threshold={self.ARP_THRESHOLD}. "
                        f"BLOCK mac={src_mac}"
                    )
                    self._install_drop_src_mac(datapath, src_mac)
                    return  # drop

                # ---------- Algorithm 1 line 3–16: Spoofing check (DEST + SRC) ----------
                is_spoof, reason = self._algo1_check_and_learn(src_ip, src_mac, dst_ip, dst_mac)
                if is_spoof:
                    self.logger.warning(
                        f"[ALGO1-SPOOFING] {reason}. BLOCK mac={src_mac} (src_ip={src_ip}, dst_ip={dst_ip})"
                    )
                    self._install_drop_src_mac(datapath, src_mac)
                    return  # drop

            # ARP an toàn (hoặc ARP reply) => vẫn flood để ARP hoạt động bình thường
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)
            return

        # ================== Non-ARP traffic: L2 forwarding so lab works ==================
        dst = eth.dst
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # cài flow forward để giảm packet-in (hành vi learning switch)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=60)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
