@load base/protocols/conn	# 在bare mode运行时必须预先读取conn.log，其余日志都可以屏蔽掉。需要其他日志时可注释该行并在命令行取消-b选项

module FlowN;

export{
    # Create an ID for the new Log stream
    redef enum Log::ID += { LOG };

    # define a record to saved the features
    type Features: record{
        uid:         string &log;            # conn记录的uid，用于匹配记录
        topN:       vector of int &log;     # 前N个负载包的包长序列
        pkt_tot:     count &optional;        # vector中已经记录包的个数，超出则放弃检测当前包，考虑使用|topN|代替
        proto:       transport_proto   &log; # 流协议
        orig_h:      addr   &log;            # 源地址
        orig_p:      port   &log;            # 源目的端口
        resp_h:      addr   &log;            # 响应地址
        resp_p:      port   &log;            # 响应端口
    };
}

# 定义记录流的前N个包
const N:count = 20;
# 定义是否记录icmp流
const no_icmp: bool = T;
# 定义是否记录ipv6流
const no_ip6: bool = T;
# 定义是否填充流长度至N
const padding:bool = F;
# 映射到对应记录的哈希表
global packet_N: table[string] of vector of int;
# 其它记录在触发 connection_remove事件时会从connection中获取

# 定义是否略过没有负载的流
const skipping = T;
# 定义是否以json格式输出
redef LogAscii::use_json = T;

event zeek_init() &priority=5{
    Log::create_stream(FlowN::LOG, [$columns=Features, $path="flowN"]);
}

# update the measures for each new packet
event new_packet(c:connection, p: pkt_hdr){

    # bool is true if this packet is tcp
    local is_tcp = p?$tcp;
    # bool is true if this packet is udp
    local is_udp = p?$udp;
    # bool is true if this packet is icmp
    local is_icmp = p?$icmp;
    # bool is true if this packet is ipv6
    local is_ip6 = p?$ip6;

    # 如果是规则不允许记录的icmp包或不允许的ipv6包则直接返回
    if((is_icmp && no_icmp) || (is_ip6 && no_ip6))
        break;

    # check if the table entries for that uid already exist
    if(!(c$uid in packet_N)){
        packet_N[c$uid] = vector();
    }

    local header_size:int = 0;
    if(is_tcp){
        header_size = p$tcp$hl;
    }
    if(is_udp || is_icmp){
        header_size = 8;
    }

    local data_size:int = 0;
    if(is_ip6){
        data_size = p$ip6$len - header_size;
    }
    else{
        data_size = p$ip$len - p$ip$hl - header_size;
    }

    # 如果传输层无负载则直接返回不做记录
    if(data_size == 0)
        break;

    # 如果当前conn已经记录超过定义的常量N个，则直接返回
    local len = |packet_N[c$uid]|;
    if(len >= N)
        break;
    
    # 开始进行记录，我们选择zeek内定义的记录方法，orig_h发起的连接负载为正，resp_h传输的负载为负
    # 通过判断包的src与conn中orig_h是否相等即可判断是否需要加负号
    local flag:int = 1;
    local src_addr = is_ip6 ? p$ip6$src : p$ip$src;
    local orig_addr = c$id$orig_h;
    flag = src_addr == orig_addr ? 1 : -1;

    packet_N[c$uid] += data_size * flag;
    
}

# if the connection is finished, write the feature to the log file
event connection_state_remove(c:connection){
	if(!(c$uid in packet_N))
		break;

    local len = |packet_N[c$uid]|;
    
    # 略过没有负载的流
    if(len == 0 && skipping)
        break;

    if(len < N && padding){
        while(len <= N){
            packet_N[c$uid] += 0;
            ++len;
        }
    }
    
    local rec = FlowN::Features($uid = c$uid, $topN = packet_N[c$uid], $pkt_tot = |packet_N[c$uid]|,
                                $proto = c$conn$proto, $orig_h = c$id$orig_h, $orig_p = c$id$orig_p,
                                $resp_h = c$id$resp_h, $resp_p = c$id$resp_p);
    
    # delete the table entries of this connection
    delete packet_N[c$uid];
    Log::write(FlowN::LOG, rec);
}
