'''
X   bigip_cm_device
X   bigip_cm_devicegroup
X   bigip_ltm_dns
X   bigip_ltm_datagroup
X   bigip_ltm_irule
X   bigip_ltm_monitor
X   bigip_ltm_node
X   bigip_ltm_persistence_profile_cookie
X   bigip_ltm_persistence_profile_dstaddr
X   bigip_ltm_persistence_profile_srcaddr
X   bigip_ltm_persistence_profile_ssl
X   bigip_ltm_policy
X   bigip_ltm_pool
X   bigip_ltm_pool_attachment  (node?  wtf would they do this like this?)
X   bigip_ltm_profile_fasthttp
X   bigip_ltm_profile_fastl4
X   bigip_ltm_profile_http2
X   bigip_ltm_profile_httpcompress
X   bigip_ltm_profile_oneconnect
X   bigip_ltm_profile_tcp
X   bigip_ltm_snat
X   bigip_ltm_snatpool
X   bigip_ltm_virtual_address
X   bigip_ltm_virtual_server
X   bigip_net_route
X   bigip_net_selfip
X   bigip_net_vlan
bigip_sys_iapp
X   bigip_sys_ntp
X   bigip_sys_provision
X   bigip_sys_snmp
X   bigip_sys_snmp_trap
'''
'''
MGMT.tm.cm.device_groups.get_collection()
MGMT.tm.sys.dns.load()
MGMT.tm.ltm.data_group.internals.get_collection()
MGMT.tm.ltm.rules.get_collection()
MGMT.tm.ltm.monitor.get_collection()
MGMT.tm.ltm.nodes.get_collection()
MGMT.tm.ltm.persistence.cookies.get_collection()
MGMT.tm.ltm.persistence.dest_addrs.get_collection()
MGMT.tm.ltm.persistence.source_addrs.get_collection()
MGMT.tm.ltm.persistence.ssls.get_collection()
MGMT.tm.ltm.policys.get_collection()
MGMT.tm.ltm.pools.get_collection()
MGMT.tm.ltm.profile.fasthttps.get_collection()
MGMT.tm.ltm.profile.fastl4s.get_collection()
MGMT.tm.ltm.profile.http2s.get_collection()
MGMT.tm.ltm.profile.http_compressions.get_collection()
MGMT.tm.ltm.profile.one_connects.get_collection()
MGMT.tm.ltm.profile.tcps.get_collection()
MGMT.tm.ltm.snats.get_collection()
MGMT.tm.ltm.snatpools.get_collection()
MGMT.tm.ltm.virtual_address_s.get_collection()
MGMT.tm.ltm.virtuals.get_collection()
MGMT.tm.net.routes.get_collection()
MGMT.tm.net.selfips.get_collection()
MGMT.tm.net.vlans.get_collection()
MGMT.tm.sys.ntp.load()
MGMT.tm.sys.provision.get_collection()
MGMT.tm.sys.snmp.load()
MGMT.tm.sys.snmp.traps_s.get_collection()

OBJLIST = [
    'MGMT.tm.cm.device_groups.get_collection()',
    'MGMT.tm.ltm.data_group.internals.get_collection()',
    'MGMT.tm.ltm.rules.get_collection()',
    'MGMT.tm.ltm.monitor.get_collection()',
    'MGMT.tm.ltm.nodes.get_collection()',
    'MGMT.tm.ltm.persistence.cookies.get_collection()',
    'MGMT.tm.ltm.persistence.dest_addrs.get_collection()',
    'MGMT.tm.ltm.persistence.source_addrs.get_collection()',
    'MGMT.tm.ltm.persistence.ssls.get_collection()',
    'MGMT.tm.ltm.policys.get_collection()',
    'MGMT.tm.ltm.pools.get_collection()',
    'MGMT.tm.ltm.profile.fasthttps.get_collection()',
    'MGMT.tm.ltm.profile.fastl4s.get_collection()',
    'MGMT.tm.ltm.profile.http2s.get_collection()',
    'MGMT.tm.ltm.profile.http_compressions.get_collection()',
    'MGMT.tm.ltm.profile.one_connects.get_collection()',
    'MGMT.tm.ltm.profile.tcps.get_collection()',
    'MGMT.tm.ltm.snats.get_collection()',
    'MGMT.tm.ltm.snatpools.get_collection()',
    'MGMT.tm.ltm.virtual_address_s.get_collection()',
    'MGMT.tm.ltm.virtuals.get_collection()',
    'MGMT.tm.net.routes.get_collection()',
    'MGMT.tm.net.selfips.get_collection()',
    'MGMT.tm.net.vlans.get_collection()',
    'MGMT.tm.sys.provision.get_collection()',
    'MGMT.tm.sys.snmp.traps_s.get_collection()',
    ]

'''
