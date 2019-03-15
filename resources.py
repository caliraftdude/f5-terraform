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


provider "bigip" {
  address = "${var.url}"
  username = "${var.username}"
  password = "${var.password}"
  token_auth = "${var.token_auth}"
  login_ref = "${var.login_ref}"
}


resource "bigip_cm_device" "my_new_device"
{
    name = "bigip300.f5.com"
    configsync_ip = "2.2.2.2"
    mirror_ip = "10.10.10.10"
    mirror_secondary_ip = "11.11.11.11"
}


resource "bigip_cm_devicegroup" "my_new_devicegroup"
{
    name = "sanjose_devicegroup"
    auto_sync = "enabled"
    full_load_on_sync = "true"
    type = "sync-only"
    device  { name = "bigip1.cisco.com"}
    device  { name = "bigip200.f5.com"}
}

resource "bigip_ltm_dns" "dns1" {
   description = "/Common/DNS1"
   name_servers = ["1.1.1.1"]
   numberof_dots = 2
   search = ["f5.com"]
}

resource "bigip_ltm_monitor" "monitor" {
  name = "/Common/terraform_monitor"
  parent = "/Common/http"
  send = "GET /some/path\r\n"
  timeout = "999"
  interval = "999"
  destination = "1.2.3.4:1234"
}

resource "bigip_ltm_pool" "pool" {
  name = "/Common/terraform-pool"
  load_balancing_mode = "round-robin"
  monitors = ["${bigip_ltm_monitor.monitor.name}","${bigip_ltm_monitor.monitor2.name}"]
  allow_snat = "yes"
  allow_nat = "yes"
}


resource "bigip_ltm_virtual_server" "http" {
  name = "/Common/terraform_vs_http"
  destination = "10.12.12.12"
  port = 80
  pool = "/Common/the-default-pool"
}

# A Virtual server with SSL enabled
resource "bigip_ltm_virtual_server" "https" {
  name = "/Common/terraform_vs_https"
  destination = "${var.vip_ip}"
  port = 443
  pool = "${var.pool}"
  profiles = ["/Common/tcp","/Common/my-awesome-ssl-cert","/Common/http"]
  source_address_translation = "automap"
  translate_address = "enabled"
  translate_port = "enabled"
  vlans_disabled = true
}

# A Virtual server with separate client and server profiles
 resource "bigip_ltm_virtual_server" "https" {
  name = "/Common/terraform_vs_https"
  destination = "10.255.255.254"
  port = 443
  client_profiles = ["/Common/clientssl"]
  server_profiles = ["/Common/serverssl"]
  source_address_translation = "automap"
}






'''
