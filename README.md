# Zeek flowN

reference: https://github.com/zeek-flowmeter/zeek-flowmeter

This project performs layer3 and layer4 network analysis and generate a set of features. These features contain the first-N packets of a flow and its 5-tuple label composed of connection's orig_h/orig_p/resp_h/resp_p/protocol.

This project outputs json log and doesn't record icmp & ipv6 flows by default.

## Configure

### Add flowN to local zeek configuration(optional)

To add flowN to the standard local configuration of zeek, edit `<zeekscriptdir>/site/local.zeek` and add

    @load flowN

### Disable Zeek packet checksum verification

Zeek discards packages with an invalid checksum by default.If users need to include invalid packages in the analysis, you need to add the line `redef ignore_checksums=T;` to the config file. If you start Zeek using command line, use option `-C` to ignore invalid checksum.

### Parameters

* `N`: The first N packets need to be recorded in a flow.The default value is 20.

* `no_icmp`: Whether to record ICMP traffic.The default value is T.

* `no_ip6`: Whether to record IPv6 traffic.The default value is T.

* `padding`: Whether to pad the topN sequence to the specified length N.The default value is F.

* `LogAscii::use_json`: Whether to write log using json.The default value is T.If it's F, flowN will output log with ASCII format.

* `skipping`: Whether to skipping flows which have no layer-4 payload at all.The default value is T.

* `disable_conn_log`: Whether to disable the conn.log.The default value is T.

## Run

Analyze a `pcap` with flowN from the command line.

    zeek flowN -r <your.pcap>

Analyze a `pcap` with a local defined flowN, as defined in `local.zeek` config.

    zeek local -r <your.pcap>

Analyze real-time traffic only using flowN from the command line and save flowN.log in current directory.Use `-b` option to run Zeek in bare-mode(don't load scripts from the base/directory).Then zeek will only generates flowN.log and conn.log(conn.log is the base log to generate flowN.log).

    zeek -i <your interface> flowN.zeek -b

## flowN.log

| Feature Name  |  Description  | Example   |
|   :----       |   :----       | :----     |
|  uid  |   The ID of the flow as given by Zeek. |   CfC5xZ3RWbb4TJG6i3  |
|   topN    |   The first N packets of the flow.    |   [460,-374,445,-252,-105,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]    |
|   proto  |   The 4 layer protocol of the flow.   | tcp   |
|  orig_h  |    Original host of the flow.  |   192.168.0.1 |
|   orig_p  |   Original port of the flow.  | 52022 |
|   resp_h  |   Response host of the flow.  |   8.8.8.8  |
|   resp_p  |   Response port of the flow.  |   80  |
