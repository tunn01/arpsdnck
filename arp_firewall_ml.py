# # arp_firewall_ml.py - PHIÊN BẢN FINAL SO SÁNH SPOOFING
# from ryu.base import app_manager
# from ryu.controller import ofp_event
# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
# from ryu.ofproto import ofproto_v1_3
# from ryu.lib.packet import packet, ethernet, arp
# from ryu.lib.packet import ether_types
# import time, joblib, warnings

# warnings.filterwarnings("ignore")
# ZERO_MAC = "00:00:00:00:00:00"

# def ip_oct(ip: str) -> int:
#     try: return int(ip.split(".")[-1])
#     except: return -1
# def mac_b(mac: str) -> int:
#     try: return int(mac.split(":")[-1], 16)
#     except: return -1

# class HybridARPFirewall(app_manager.RyuApp):
#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.ARP_THRESHOLD = 20
#         self.arp_cache = {}
#         self.packet_counts = {}
#         self.start_time = {}
#         try:
#             bundle = joblib.load("arp_mlp.joblib")
#             self.model = bundle["model"]
#             self.features = bundle["features"]
#             self.logger.info("[ML] Model Loaded. Ready for Cold-Start Test.")
#         except:
#             self.logger.error("Model not found!")

#     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
#     def switch_features_handler(self, ev):
#         dp = ev.msg.datapath
#         ofp = dp.ofproto
#         parser = dp.ofproto_parser
#         match = parser.OFPMatch()
#         actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
#         dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match,
#                                       instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]))
#         self.logger.info("Switch connected.")

#     def _drop_mac(self, dp, mac_block):
#         parser = dp.ofproto_parser
#         mod = parser.OFPFlowMod(datapath=dp, priority=100, match=parser.OFPMatch(eth_src=mac_block), instructions=[])
#         dp.send_msg(mod)
#         self.logger.warning(f"   >>> [MITIGATION] DROP Rule installed for {mac_block}")

#     def _ml_score(self, rowdict):
#         x = [[rowdict.get(f, 0) for f in self.features]]
#         return self.model.predict_proba(x)[0][1]

#     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#     def _packet_in(self, ev):
#         msg = ev.msg
#         dp = msg.datapath
#         dpid = dp.id
#         ofp = dp.ofproto
#         parser = dp.ofproto_parser
#         in_port = msg.match["in_port"]
#         pkt = packet.Packet(msg.data)
#         eth = pkt.get_protocol(ethernet.ethernet)
        
#         if eth.ethertype != ether_types.ETH_TYPE_ARP:
#             # Forwarding packets khác
#             actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
#             out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
#             dp.send_msg(out)
#             return

#         a = pkt.get_protocol(arp.arp)
#         if a and a.opcode == arp.ARP_REQUEST:
#             src_ip, src_mac = a.src_ip, eth.src
            
#             # --- 1. RULE-BASED CHECK (Algorithm 1) ---
#             # Logic: Nếu có trong Cache thì check, chưa có thì HỌC
#             rule_verdict = "SAFE"
#             if src_ip in self.arp_cache:
#                 if self.arp_cache[src_ip] != src_mac:
#                     rule_verdict = "ATTACK"
#                     self.logger.warning(f"[RULE] Detected Spoofing (Mismatch in Cache).")
#                     self._drop_mac(dp, src_mac)
#                     return
#             else:
#                 # Đây là điểm yếu: Cache chưa có => Rule tin tưởng và học
#                 rule_verdict = "SAFE (Learning)"
#                 # (Tạm thời chưa lưu vào cache vội để xem AI nói gì)

#             # --- 2. AI CHECK (Vượt trội) ---
#             row = {
#                 "opcode": 1, "src_ip_oct": ip_oct(src_ip), "dst_ip_oct": ip_oct(a.dst_ip),
#                 "src_mac_b": mac_b(src_mac), "dst_mac_b": mac_b(a.dst_mac),
#                 "is_request": 1, "is_reply": 0, "is_gratuitous": 1 if src_ip==a.dst_ip else 0,
#                 "dst_mac_zero": 1 if a.dst_mac==ZERO_MAC else 0, "req_rate_1s": 1, "mac_change_count": 0
#             }
            
#             prob = self._ml_score(row)
            
#             if prob >= 0.85:
#                 # Nếu AI thấy tấn công, dù Rule bảo Safe
#                 self.logger.warning(f"[AI-SUPERIOR] AI Blocked {src_ip} -> {src_mac}. (Rule said: {rule_verdict}, but AI Prob={prob:.2f})")
#                 self._drop_mac(dp, src_mac)
#                 return
            
#             # Nếu cả 2 đều an toàn thì mới lưu vào Cache
#             if src_ip not in self.arp_cache:
#                 self.arp_cache[src_ip] = src_mac
#                 self.logger.info(f"[LEARN] Trusted and added to Cache: {src_ip} -> {src_mac}")

#         # Forwarding
#         actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
#         out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
#         dp.send_msg(out)


# arp_firewall_final_all.py - CHẠY ĐƯỢC CẢ FLOODING VÀ SPOOFING
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib.packet import ether_types
import time, joblib, warnings

warnings.filterwarnings("ignore")
ZERO_MAC = "00:00:00:00:00:00"

def ip_oct(ip: str) -> int:
    try: return int(ip.split(".")[-1])
    except: return -1
def mac_b(mac: str) -> int:
    try: return int(mac.split(":")[-1], 16)
    except: return -1

class HybridARPFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ARP_THRESHOLD = 20  # Ngưỡng tĩnh theo Algorithm 1
        self.arp_cache = {}
        self.packet_counts = {}
        self.start_time = {}
        try:
            bundle = joblib.load("arp_mlp.joblib")
            self.model = bundle["model"]
            self.features = bundle["features"]
            self.logger.info("[ML] Model Loaded. Ready for ALL Scenarios.")
        except:
            self.logger.error("Model not found!")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match,
                                      instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]))
        self.logger.info("Switch connected.")

    def _drop_mac(self, dp, mac_block):
        parser = dp.ofproto_parser
        mod = parser.OFPFlowMod(datapath=dp, priority=100, match=parser.OFPMatch(eth_src=mac_block), instructions=[])
        dp.send_msg(mod)
        self.logger.warning(f"   >>> [MITIGATION] DROP Rule installed for {mac_block}")

    def _rate_limit_req(self, dpid, src_ip):
        now = time.time()
        self.packet_counts.setdefault(dpid, {})
        self.start_time.setdefault(dpid, {})
        if src_ip not in self.packet_counts[dpid]:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now
        if now - self.start_time[dpid][src_ip] > 1.0:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now
        self.packet_counts[dpid][src_ip] += 1
        # Trả về (Is_Safe, Current_Rate)
        return self.packet_counts[dpid][src_ip] <= self.ARP_THRESHOLD, self.packet_counts[dpid][src_ip]

    def _ml_score(self, rowdict):
        x = [[rowdict.get(f, 0) for f in self.features]]
        return self.model.predict_proba(x)[0][1]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype != ether_types.ETH_TYPE_ARP:
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        a = pkt.get_protocol(arp.arp)
        if a and a.opcode == arp.ARP_REQUEST:
            src_ip, src_mac = a.src_ip, eth.src
            
            # --- 1. CHECK FLOODING (Rate Limit) ---
            is_safe_rate, rate = self._rate_limit_req(dpid, src_ip)
            
            if not is_safe_rate:
                self.logger.warning(f"[RULE-FLOODING] Blocked {src_ip}. Rate={rate} > 20 (Algorithm 1)")
                self._drop_mac(dp, src_mac)
                return

            # --- 2. CHECK SPOOFING (Cache Check) ---
            if src_ip in self.arp_cache:
                if self.arp_cache[src_ip] != src_mac:
                    self.logger.warning(f"[RULE-SPOOFING] Blocked {src_ip}. Mismatch in Cache.")
                    self._drop_mac(dp, src_mac)
                    return
            
            # --- 3. CHECK AI (Cho các trường hợp lọt lưới 1 và 2) ---
            # Quan trọng: Truyền 'rate' thực tế vào AI, không phải số 1
            row = {
                "opcode": 1, "src_ip_oct": ip_oct(src_ip), "dst_ip_oct": ip_oct(a.dst_ip),
                "src_mac_b": mac_b(src_mac), "dst_mac_b": mac_b(a.dst_mac),
                "is_request": 1, "is_reply": 0, "is_gratuitous": 1 if src_ip==a.dst_ip else 0,
                "dst_mac_zero": 1 if a.dst_mac==ZERO_MAC else 0, 
                "req_rate_1s": rate, # <--- ĐIỂM SỬA QUAN TRỌNG
                "mac_change_count": 0
            }
            
            prob = self._ml_score(row)
            
            if prob >= 0.85:
                if rate < 20:
                    self.logger.warning(f"[AI-FLOOD-EVASION] AI Blocked {src_ip}. Rate={rate} < 20 (Rule missed, AI caught!)")
                else:
                    self.logger.warning(f"[AI-SPOOF-COLDSTART] AI Blocked {src_ip}. (Cache empty, AI caught!)")
                
                self._drop_mac(dp, src_mac)
                return
            
            # Nếu an toàn thì học
            if src_ip not in self.arp_cache:
                self.arp_cache[src_ip] = src_mac

        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)