#!/usr/bin/python
import sys
import os
import logging
import getpass
from urlparse import urlparse

from f5.bigip import ManagementRoot
import icontrol.exceptions
import f5.sdk_exception

# The number of objects that Terrform can actually use is a small subset of the F5 cannon, so it makes sense to 
# trim the list we will collect data on to only those we have a use for
OBJLIST = [
    'tm.cm.devices',
    'tm.cm.device_groups',
    'tm.ltm.data_group.internals',
    'tm.ltm.rules',
    'tm.ltm.monitor',
    'tm.ltm.nodes',
    'tm.ltm.persistence.cookies',
    'tm.ltm.persistence.dest_addrs',
    'tm.ltm.persistence.source_addrs',
    'tm.ltm.persistence.ssls',
    'tm.ltm.policys',
    'tm.ltm.pools',
    'tm.ltm.profile.fasthttps',
    'tm.ltm.profile.fastl4s',
    'tm.ltm.profile.http2s',
    'tm.ltm.profile.http_compressions',
    'tm.ltm.profile.one_connects',
    'tm.ltm.profile.tcps',
    'tm.ltm.snats',
    'tm.ltm.snatpools',
    'tm.ltm.virtual_address_s',
    'tm.ltm.virtuals',
    'tm.net.routes',
    'tm.net.selfips',
    'tm.net.vlans',
    'tm.sys.provision',
    'tm.sys.snmp.traps_s',
    'tm.sys.dns',
    'tm.sys.ntp',
    'tm.sys.snmp',
    ]


# The object library will be the library that has all the configuration data in it.  The top level object is a dictionary that uses
# the above list as a key to the type of object.  That will always lead to a list of dictionaries.  The dictionaries in the list are
# the configuration data of each instance of said object
OBJECT_LIBRARY = {}

# Use these for accessing the bigip - not sure how the tf file should use these..
USERNAME = ""
PASSWORD = ""

#################################################################
#   Main program
#################################################################
def main():


    global USERNAME
    global PASSWORD
    test = 0

    if not test:
        USERNAME = getpass.getpass(prompt="Username:\t")
        PASSWORD = getpass.getpass(prompt="Password:\t")
        DEVICE = raw_input("IP Address of device to copy config from: ")
    else:
        USERNAME = "admin"
        PASSWORD = "admin"
        DEVICE = "10.1.1.241"

    # connect to the BigIP
    try:
        if not check_ping(DEVICE):
            log.exception("Unable to ping IP of device")
            sys.exit(-1)

        


        MGMT = ManagementRoot(DEVICE, USERNAME, PASSWORD)

    except icontrol.exceptions.iControlUnexpectedHTTPError:
        log.exception("Critical failure during login")
        sys.exit(-1)

    parseObjects(MGMT)
    log.info("Device successfully parsed...")

    # Create output directory
    try:
        path = os.getcwd()
        path += "/TF-" + DEVICE
        os.mkdir(path)
        path += "/"

    except OSError:
        log.exception("Unable to create output directory (permissions issue?)")


    # This should be re-written to break this up into a bunch of different files..  probably a file per object-type
    # It may also make sense to put into its own directory and put it into exception handling..
    with open(path+"bigip.tf", "w") as fhandle:
        writeProvider(fhandle)
        fhandle.flush()

    with open(path+"tm.cm.devices.tf", "w") as fhandle:
        writeDevices(fhandle)
        fhandle.flush()

    with open(path+"tm.cm.device_groups.tf", "w") as fhandle:
        writeDevicesGroups(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.data_group.internals.tf", "w") as fhandle:
        writeDataGroupInternals(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.rules.tf", "w") as fhandle:
        writeRules(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.monitor.tf", "w") as fhandle:
        writeMonitors(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.nodes.tf", "w") as fhandle:
        writeNodes(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.persistence.cookies.tf", "w") as fhandle:
        writePersistenceCookies(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.persistence.dest_addrs.tf", "w") as fhandle:
        writePersistenceDestAddr(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.persistence.source_addrs.tf", "w") as fhandle:
        writePersistenceSrcAddr(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.persistence.ssls.tf", "w") as fhandle:
        writePersistenceSSL(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.policys.tf", "w") as fhandle:
        writePolicies(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.pools.tf", "w") as fhandle:
        writePool(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.profile.fasthttps.tf", "w") as fhandle:
        writeProfileFastHTTPS(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.profile.fastl4s.tf", "w") as fhandle:
        writeProfileFastL4(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.profile.http2s.tf", "w") as fhandle:
        writeProfileHTTP2S(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.profile.http_compressions.tf", "w") as fhandle:
        writeHTTPCompressions(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.profile.one_connects.tf", "w") as fhandle:
        writeProfileOneConnect(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.profile.tcps.tf", "w") as fhandle:
        writeProfileTCP(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.snat.tf", "w") as fhandle:
        writeSnat(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.snatpool.tf", "w") as fhandle:
        writeSnatPool(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.virtual_address_s.tf", "w") as fhandle:
        writeVirtualAddress(fhandle)
        fhandle.flush()

    with open(path+"tm.ltm.virtuals.tf", "w") as fhandle:
        writeVirtual(fhandle)
        fhandle.flush()

    with open(path+"tm.net.route.tf", "w") as fhandle:
        writeRoute(fhandle)
        fhandle.flush()

    with open(path+"tm.net.selfip.tf", "w") as fhandle:
        writeSelfIP(fhandle)
        fhandle.flush()

    with open(path+"tm.net.vlan.tf", "w") as fhandle:
        writeVlan(fhandle)
        fhandle.flush()

    with open(path+"tm.sys.provision.tf", "w") as fhandle:
        writeProvision(fhandle)
        fhandle.flush()

    with open(path+"tm.sys.snmp.traps_s.tf", "w") as fhandle:
        writeSNMPTraps(fhandle)
        fhandle.flush()

    with open(path+"tm.sys.dns.tf", "w") as fhandle:
        writeDNS(fhandle)
        fhandle.flush()

    with open(path+"tm.sys.ntp.tf", "w") as fhandle:
        writeNTP(fhandle)
        fhandle.flush()

    with open(path+"tm.sys.snmp.tf", "w") as fhandle:
        writeSNMP(fhandle)
        fhandle.flush()



def parseObjects(MGMT):
    for OBJ in OBJLIST:
        instance_list = []

        log.info("{} =================================================".format(OBJ.upper()) )

        if OBJ == "tm.net.vlans":
            pass

        # Monitors are horribly organized as tm.ltm.monitor is an Organizing Container, which meants that it only has a bunch of reference links to
        # monitor types in it.  This is utterly useless as the api cannot really translate that to anything, so we have to handle monitors
        # differently so that we land on a Collection instead of an Oragnizing Container
        if OBJ == 'tm.ltm.monitor':

            # This will go through some convoluted steps to extract each monitor type and pass its Collection to parseColection
            parse_monitor_oc(MGMT, instance_list)

            # Short cut the rest of this function and continue with the loop
            continue

        try:
            collection = eval('MGMT.' + OBJ + '.get_collection()')
        except (f5.sdk_exception.LazyAttributesRequired, AttributeError):
            # Another foul hack.. There is *no* programic way to determine if this is collection or an unnamed resource prior
            # to this call, so if it throws this exception, assume its an unnamed resrouce and use load instead.  To add to the annoyance, 
            # tm.sys.dns throws the LazyAttributes exception while ntp and snmp throw the Attribute error
            collection = eval('MGMT.' + OBJ + '.load()')

        parseCollection(MGMT, collection, instance_list)

        OBJECT_LIBRARY[OBJ] = instance_list


def parseCollection(MGMT, nodes, instance_list):
 
    # Walk through the collection passed to us
    if type(nodes) is not list:
        instance_dict = {}

        # Objects like tm.sys.dns have no list which can cause problems in parseDictionary that needs the obj
        # we are working with.  Pass the nodes object instead so it resolves
        for key, value in nodes.attrs.iteritems():
            parseDictionary(key, value, instance_dict, nodes)

        instance_list.append(instance_dict)
    else:   
        for node in nodes:
            instance_dict = {}
            # For each item, walk the attributes section.  Since these can be dynamically there or not
            # depending on if configured (we can't rely on a 'none'), its best to go this way then
            # set up a complex expectation of exceptions.  The API should have been from friendly here
            try:
                for key, value in node.attrs.iteritems():
                    parseDictionary(key, value, instance_dict, node)

            except AttributeError:
                # Endpoints like tm.sys.provision drop straight into a resource, so we will throw an attr exception.
                # check for this first and assume that we have a dictionary of key-value pairs already (bad assumption? monitors would fall
                # under this case as well so to make this truely genereic you would need to determine what sort of end point you landed
                # on and there is no way to determine that.
                for key, value in node.iteritems():
                    parseDictionary(key, value, instance_dict, node)

            instance_list.append(instance_dict)


def parseDictionary(key, value, instance_dict, node=None):
    # Determine the value type since its possible to be dict, str, number, etc..
    # This might need to be a recursive function.. will determine later...
    # There are some strong arguments that this should be a recursive function but for now I think its okay for it not to be.
    # Should this get used in a more comprehensive context there are good arguements to do so.
    if type(value) is unicode:
        log.info('\t{}: {}'.format(key, value))
        instance_dict.update({key:value})

    if type(value) is int:
        log.info('\t{}: {}'.format(key, value))
        instance_dict.update({key:value})

    if type(value) is list:
        log.info('\t{}:'.format(key))
        instance_dict.update({key:value})
        
        for item in value:
            log.info('\t\t{}'.format(item))

    if type(value) is dict:
        log.info('\t{}:'.format(key))
        instance_dict[key] = value

        # If this is a subcollection, we will add some elements to the dictionary so it can easily be resolved later
        if "isSubcollection" in value:
            # This is a hassle.. we will get a link like this:
            #       https://localhost/mgmt/tm/ltm/pool/~Common~HSL-Logging-Pool/members?ver=13.1.0.8
            # what we need to do is strip that last element off the path (members in this case)
            # munge the 's'/'_s' and then exec against the node to get the subcollection..
            try:
                url = urlparse(value['link']).path.split('/')[-1]

                # This.. ugh..
                if url.endswith('s'):
                    url += '_s'
                else:
                    url += 's'

                # Evaluate the collection using the node object and concatenating the last element and get_collection()
                members = eval('node.' + url + '.get_collection()')
                members_list = []

                # The members for a pool are under name - not sure this is universal though (not counting on it)
                for member in members:
                    # XXX need to import the entire object.. tm.net.vlan is example for "interfaces"
                    # members_list.append(member.name)
                    members_list.append(member)

                # add the list into the dictinary
                instance_dict[key]['members'] = members_list
            except AttributeError:
                # *shouldn't* get here anymore, but just in case something doesn't resolve down the road
                pass

        for k, v in value.iteritems():
            log.info('\t\t{}: {}'.format(k, v))


def parse_monitor_oc(MGMT, instance_list):
    monitors = MGMT.tm.ltm.monitor.get_collection()
    for url in monitors:
        
        # WARNING: non-pythonic code ahead...
        # strip out the monitor type from the reference link        
        monitor_t = (url['reference']['link'].split('/')[-1]).split('?')[0]

        # Build a string for labeling
        label = 'tm.ltm.monitor.' + monitor_t

        # For some reason there is a monitor reference to none.. skip it
        if monitor_t == 'none':
            continue

        # Because the API meshed english pluralities with API calls, we have to handle english rules in our collection names
        if monitor_t.endswith('s'):
            monitor_t += '_s'
        else:
            monitor_t += 's'

        # And because there are inconsistencies we also have to handle dashes to underscores
        monitor_t = monitor_t.replace(u'-', u'_')

        # Use a hack in order get the collection..
        collection = eval('MGMT.tm.ltm.monitor.' +  monitor_t + '.get_collection()')

        # with a collection in hand we can now go back to parseCollection
        log.info("\t{} =================================================".format(label.upper()) )
        parseCollection(MGMT, collection, instance_list)

        OBJECT_LIBRARY[label] = instance_list

#################################################################
#   Terraform output routines
#################################################################
def writeProvider(fhandle):
    fhandle.write("#  NOTE - You need to provide username and password variables\n")
    fhandle.write("#############################################################\n")
    fhandle.write("provider \"bigip\" { \n")
    fhandle.write("\taddress = \"{}\"\n".format(OBJECT_LIBRARY["tm.cm.devices"][0]["managementIp"]) )
    fhandle.write("\tusername = \"{}\"\n".format('${var.username}'))
    fhandle.write("\tpassword = \"{}\"\n".format('${var.password}'))
    fhandle.write("}\n\n")

def writeDevices(fhandle):
    for obj in OBJECT_LIBRARY["tm.cm.devices"]:
        fhandle.write("# devices {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_cm_device\" \"{}\" {{ \n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tconfigsync_ip = \"{}\"\n".format(obj["configsyncIp"]) )
        fhandle.write("\tmirror_ip = \"{}\"\n".format(obj["mirrorIp"]) )            
        fhandle.write("\tmirror_secondary_ip = \"{}\"\n".format(obj["mirrorSecondaryIp"]) )

        fhandle.write("}\n\n")

def writeDevicesGroups(fhandle):
    for obj in OBJECT_LIBRARY["tm.cm.device_groups"]:
        fhandle.write("# device group {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_cm_devicegroup\" \"{}\" {{ \n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tauto_sync = \"{}\"\n".format(obj["autoSync"]) )
        fhandle.write("\tfull_load_on_sync = \"{}\"\n".format(obj["fullLoadOnSync"]) )            
        fhandle.write("\ttype = \"{}\"\n".format(obj["type"]) )

        for device in obj["devicesReference"]["members"]:
            fhandle.write("\tdevice {{ name = \"{}\" }} \n".format(device.name) )  # XXX Not sure about this..

        fhandle.write("}\n\n")

def writeDataGroupInternals(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.data_group.internals"]:
        fhandle.write("# datagroup {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_datagroup\" \"{}\" {{ \n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\ttype = \"{}\"\n".format(obj["type"]) )

        for record in obj["records"]:
            fhandle.write("\trecord { \n" )
            fhandle.write("\t\tname = \"{}\"\n".format(record["name"]) )
            fhandle.write("\t\tdata = \"{}\"\n".format(record["data"]) )
        
            fhandle.write("\t} \n")

        fhandle.write("}\n\n")

def writeRules(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.rules"]:
        fhandle.write("# irule {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_irule\" \"{}\" {{".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tirule = << EOF \n{}\nEOF\n".format(obj["apiAnonymous"]) )

        fhandle.write("}\n\n")

def writeMonitors(fhandle):
    return
    # XXX Because of the changes to parseDictionary - I am going to have to rethink this...
    for obj in OBJECT_LIBRARY["tm.ltm.monitor"]:
        fhandle.write("# monitor {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_monitor\" \"{}\" {{".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )            
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )            
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )    

        fhandle.write("}\n\n")

def writeNodes(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.nodes"]:
        fhandle.write("# nodes {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_nodes\" \"{}\" {{ \n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\taddress = \"{}\"\n".format(obj["address"]) )
        fhandle.write("\tconnection_limit = \"{}\"\n".format(obj["connectionLimit"]) )            
        fhandle.write("\tdynamic_ratio = \"{}\"\n".format(obj["dynamicRatio"]) )
        fhandle.write("\tmonitor = \"{}\"\n".format(obj["monitor"]) )
        fhandle.write("\trate_limit = \"{}\"\n".format(obj["rateLimit"]) )            
        fhandle.write("\tfqdn = {{ address_family = \"{}\", interval = \"{}\" }}\n".format(obj["fqdn"]["addressFamily"], obj["fqdn"]["interval"]) )    

        fhandle.write("}\n\n")

def writePersistenceCookies(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.persistence.cookies"]:
        fhandle.write("# persistence cookie {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_persistence_profile_cookie\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )
        fhandle.write("\tmatch_across_pools = \"{}\"\n".format(obj["matchAcrossPools"]) )            
        fhandle.write("\tmatch_across_services = \"{}\"\n".format(obj["matchAcrossServices"]) )
        fhandle.write("\tmatch_across_virtuals = \"{}\"\n".format(obj["matchAcrossVirtuals"]) )
        fhandle.write("\ttimeout = \"{}\"\n".format(obj["timeout"]) )            
        fhandle.write("\toverride_conn_limit = \"{}\"\n".format(obj["overrideConnectionLimit"]) )    
        fhandle.write("\talways_send = \"{}\"\n".format(obj["alwaysSend"]) )
        fhandle.write("\tcookie_encryption = \"{}\"\n".format(obj["cookieEncryption"]) )
        fhandle.write("\tcookie_encryption_passphrase = \"{}\"\n".format("XXX NOT IMPLEMENTED") )            
        fhandle.write("\tcookie_name = \"{}\"\n".format(obj["cookieName"]) )
        fhandle.write("\texpiration = \"{}\"\n".format(obj["expiration"]) )
        fhandle.write("\thash_length = \"{}\"\n".format(obj["hashLength"]) )            

        fhandle.write("}\n\n")

def writePersistenceDestAddr(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.persistence.dest_addrs"]:
        fhandle.write("# persistence dest addrs {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_persistence_profile_dstaddr\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )
        fhandle.write("\tmatch_across_pools = \"{}\"\n".format(obj["matchAcrossPools"]) )            
        fhandle.write("\tmatch_across_services = \"{}\"\n".format(obj["matchAcrossServices"]) )
        fhandle.write("\tmatch_across_virtuals = \"{}\"\n".format(obj["matchAcrossVirtuals"]) )
        fhandle.write("\tmirror = \"{}\"\n".format(obj["mirror"]) )            
        fhandle.write("\ttimeout = \"{}\"\n".format(obj["timeout"]) )
        fhandle.write("\toverride_conn_limit = \"{}\"\n".format(obj["overrideConnectionLimit"]) )
        fhandle.write("\thash_algorithm = \"{}\"\n".format(obj["hashAlgorithm"]) )
        fhandle.write("\tmask = \"{}\"\n".format(obj["mask"]) )            

        fhandle.write("}\n\n")

def writePersistenceSrcAddr(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.persistence.source_addrs"]:
        fhandle.write("# Persistence Source Address {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_persistence_profile_srcaddr\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )
        fhandle.write("\tmatch_across_pools = \"{}\"\n".format(obj["matchAcrossPools"]) )            
        fhandle.write("\tmatch_across_services = \"{}\"\n".format(obj["matchAcrossServices"]) )
        fhandle.write("\tmatch_across_virtuals = \"{}\"\n".format(obj["matchAcrossVirtuals"]) )
        fhandle.write("\tmirror = \"{}\"\n".format(obj["mirror"]) )            
        fhandle.write("\ttimeout = \"{}\"\n".format(obj["timeout"]) )
        fhandle.write("\toverride_conn_limit = \"{}\"\n".format(obj["overrideConnectionLimit"]) )
        fhandle.write("\thash_algorithm = \"{}\"\n".format(obj["hashAlgorithm"]) )
        fhandle.write("\tmap_proxies = \"{}\"\n".format(obj["mapProxies"]))
        fhandle.write("\tmask = \"{}\"\n".format(obj["mask"]) )             
 
        fhandle.write("}\n\n")

def writePersistenceSSL(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.persistence.ssls"]:
        fhandle.write("# Persistence SSL {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_persistence_profile_ssl\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )
        fhandle.write("\tmatch_across_pools = \"{}\"\n".format(obj["matchAcrossPools"]) )            
        fhandle.write("\tmatch_across_services = \"{}\"\n".format(obj["matchAcrossServices"]) )
        fhandle.write("\tmatch_across_virtuals = \"{}\"\n".format(obj["matchAcrossVirtuals"]) )
        fhandle.write("\tmirror = \"{}\"\n".format(obj["mirror"]) )            
        fhandle.write("\ttimeout = \"{}\"\n".format(obj["timeout"]) )
        fhandle.write("\toverride_conn_limit = \"{}\"\n".format(obj["overrideConnectionLimit"]) )


        fhandle.write("}\n\n")

def writePolicies(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.policys"]:
        fhandle.write("# Policies {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_policy\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tstrategy = \"{}\"\n".format(obj["strategy"]) )
        fhandle.write("\trequires = \"{}\"\n".format(obj["requires"]) )            
        fhandle.write("\t# published_copy = \"{}\"\n".format("NOT IMPLEMENTED") )
        fhandle.write("\tcontrols = \"{}\"\n".format(obj["controls"]) )
        
        for rule in obj["rulesReference"]["members"]:
            fhandle.write("\trule = { \n")
            fhandle.write("\t\tname = \"{}\"\n".format(rule.name) )  
            fhandle.write("\t\t# xxx THIS IS NOT FULLY IMPLEMENTED\n")  
            fhandle.write("\t}\n")

        fhandle.write("}\n\n")

def writePool(fhandle):
    for pool in OBJECT_LIBRARY["tm.ltm.pools"]:
        # First, write out the pool object
        fhandle.write("# Pool {} ######################################################\n".format(pool["name"].split("/")[-1]))
        fhandle.write("resource \"bigip_ltm_pool\" \"{}\" ".format(pool["name"].split("/")[-1]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(pool["name"]))
        fhandle.write("\tallow_snat = \"{}\"\n".format(pool["allowSnat"]))
        fhandle.write("\tallow_nat = \"{}\"\n".format(pool["allowNat"]))

        if "loadBalancingMode" in pool.keys():  fhandle.write("\tload_balancing_mode = \"{}\"\n".format(pool["loadBalancingMode"]))
        if "monitor" in pool.keys():            fhandle.write("\tmonitors = [\"{}\"]\n".format(pool["monitor"]))

        fhandle.write("")
        fhandle.write("}\n\n")

        # I am not sure why they chose to detach the node members from the pool declaration, so do the attachment
        # object directly after the pool.  The way its declared is a pita.. so we need to do a little tap-dancing too..
        for node in pool["membersReference"]["members"]:
            fhandle.write("resource \"bigip_ltm_pool_attachment\" \"{}\" ".format(pool["name"].split("/")[-1]))
            fhandle.write("{ \n")
            fhandle.write("\tpool = \"{}\"\n".format(pool["name"]))
            
            # Subcollections put the obj type into the list, so we need to access these a little differently
            fhandle.write("\tnode = \"{}\"\n".format(node.fullPath + ":" + node.name.split(":")[1]))
            fhandle.write("}\n")

        fhandle.write("\n\n")

def writeProfileFastHTTPS(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.profile.fasthttps"]:
        fhandle.write("# Profile FastHTTPS {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_profile_fasthttp\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )
        fhandle.write("\tidle_timeout = \"{}\"\n".format(obj["idleTimeout"]) )            
        fhandle.write("\tconnpoolidle_timeoutoverride = \"{}\"\n".format(obj["connpoolIdleTimeoutOverride"]) )
        fhandle.write("\tconnpool_maxreuse = \"{}\"\n".format(obj["connpoolMaxReuse"]) )
        fhandle.write("\tconnpool_maxsize = \"{}\"\n".format(obj["connpoolMaxSize"]) )            
        fhandle.write("\tconnpool_minsize = \"{}\"\n".format(obj["connpoolMinSize"]) )    
        fhandle.write("\tconnpool_replenish = \"{}\"\n".format(obj["connpoolReplenish"]) )
        fhandle.write("\tconnpool_step = \"{}\"\n".format(obj["connpoolStep"]) )
        fhandle.write("\tforcehttp_10response = \"{}\"\n".format(obj["forceHttp_10Response"]) )            
        fhandle.write("\tmaxheader_size = \"{}\"\n".format(obj["maxHeaderSize"]) )
        
        fhandle.write("}\n\n")

def writeProfileFastL4(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.profile.fastl4s"]:
        fhandle.write("# Profile FastL4 {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_profile_fastl4\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tpartition = \"{}\"\n".format(obj["partition"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )            
        fhandle.write("\tclient_timeout = \"{}\"\n".format(obj["clientTimeout"]) )
        fhandle.write("\texplicitflow_migration = \"{}\"\n".format(obj["explicitFlowMigration"]) )
        fhandle.write("\thardware_syncookie = \"{}\"\n".format(obj["hardwareSynCookie"]) )            
        fhandle.write("\tidle_timeout = \"{}\"\n".format(obj["idleTimeout"]) )    
        fhandle.write("\tiptos_toclient = \"{}\"\n".format(obj["ipTosToClient"]) )
        fhandle.write("\tiptos_toserver = \"{}\"\n".format(obj["ipTosToServer"]) )
        fhandle.write("\tkeepalive_interval = \"{}\"\n".format(obj["keepAliveInterval"]) )            

        fhandle.write("}\n\n")

def writeProfileHTTP2S(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.profile.http2s"]:
        fhandle.write("# Profile HTTP2S {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_profile_http2\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )
        fhandle.write("\tconcurrent_streams_per_connection = \"{}\"\n".format(obj["concurrentStreamsPerConnection"]) )            
        fhandle.write("\tconnection_idle_timeout = \"{}\"\n".format(obj["connectionIdleTimeout"]) )
        
        fhandle.write("\tactivation_modes = [")
        for am in obj["activationModes"]:
            fhandle.write("\"{}\",".format(am) )
        fhandle.write("]\n")

        fhandle.write("}\n\n")

def writeHTTPCompressions(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.profile.http_compressions"]:
        fhandle.write("# Profile HTTP Compressions {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_profile_httpcompress\" \"{}\" {{\n".format(obj["name"]) )
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )

        fhandle.write("\turi_exclude = [")
        for uri in obj["uriExclude"]:
            fhandle.write("\"{}\",".format(uri))
        fhandle.write("]\n")
        
        fhandle.write("\turi_include = [")
        for uri in obj["uriInclude"]:
            fhandle.write("\"{}\",".format(uri))
        fhandle.write("]\n")
 
        fhandle.write("\tcontent_type_exclude = [")
        for uri in obj["contentTypeExclude"]:
            fhandle.write("\"{}\",".format(uri))
        fhandle.write("]\n")

        fhandle.write("\tcontent_type_include = [")
        for uri in obj["contentTypeInclude"]:
            fhandle.write("\"{}\",".format(uri))
        fhandle.write("]\n")

        fhandle.write("}\n\n")

def writeProfileOneConnect(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.profile.one_connects"]:
        fhandle.write("# Profile OneConnect {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_profile_oneconnect\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tpartition = \"{}\"\n".format(obj["partition"]) )
        fhandle.write("\tdefaults_from = \"{}\"\n".format(obj["defaultsFrom"]) )            
        fhandle.write("\tidle_timeout_override = \"{}\"\n".format(obj["idleTimeoutOverride"]) )
        fhandle.write("\tmax_age = \"{}\"\n".format(obj["maxAge"]) )
        fhandle.write("\tmax_reuse = \"{}\"\n".format(obj["maxReuse"]) )            
        fhandle.write("\tmax_size = \"{}\"\n".format(obj["maxSize"]) )    
        fhandle.write("\tshare_pools = \"{}\"\n".format(obj["sharePools"]) )
        fhandle.write("\tsource_mask = \"{}\"\n".format(obj["sourceMask"]) )
        fhandle.write("}\n\n")

def writeProfileTCP(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.profile.tcps"]:
        fhandle.write("# Profile TCP {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_profile_tcp\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tidle_timeout = \"{}\"\n".format(obj["idleTimeout"]) )
        fhandle.write("\tclose_wait_timeout = \"{}\"\n".format(obj["closeWaitTimeout"]) )            
        fhandle.write("\tfinwait_2timeout = \"{}\"\n".format(obj["finWait_2Timeout"]) )
        fhandle.write("\tfinwait_timeout = \"{}\"\n".format(obj["finWaitTimeout"]) )
        fhandle.write("\tkeepalive_interval = \"{}\"\n".format(obj["keepAliveInterval"]) )            
        fhandle.write("\tdeferred_accept = \"{}\"\n".format(obj["deferredAccept"]) )    
        fhandle.write("\tfast_open = \"{}\"\n".format(obj["fastOpen"]))

        fhandle.write("}\n\n")

def writeSnat(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.snats"]:
        fhandle.write("# snat {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_snat\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tpartition = \"{}\"\n".format(obj["partition"]) )
        
        fhandle.write("\torigins = [")
        for origin in obj["origins"]:
            fhandle.write("\"{}\",".format(origin["name"]) )
        fhandle.write("]\n")
        
        fhandle.write("\tsnatpool = \"{}\"\n".format(obj["snatpool"]) )
        fhandle.write("\tmirror = \"{}\"\n".format(obj["mirror"]) )
        fhandle.write("\tautolasthop = \"{}\"\n".format(obj["autoLasthop"]) )            
        fhandle.write("\tsourceport = \"{}\"\n".format(obj["sourcePort"]) )
        
        fhandle.write("\t#translation = \"{}\"\n".format("NOT IMPLEMENTED") )            
        fhandle.write("\t#vlansdisabled = \"{}\"\n".format("NOT IMPLEMENTED") )

        fhandle.write("\tvlans = [")
        for vlan in obj["vlans"]:
            fhandle.write("\"{}\",".format(vlan) )
        fhandle.write("]\n")

        fhandle.write("}\n\n")

def writeSnatPool(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.snatpools"]:
        fhandle.write("# snatpool {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_snatpool\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )

        fhandle.write("\tmembers = [")
        for member in obj["members"]:
            fhandle.write("\"{}\",".format(member.split("/")[-1]))
        fhandle.write("]\n")
        
        fhandle.write("}\n\n")

def writeVirtualAddress(fhandle):
    for obj in OBJECT_LIBRARY["tm.ltm.virtual_address_s"]:
        fhandle.write("# Virtual Address {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_ltm_virtual_address\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tadvertise_route = \"{}\"\n".format(obj["routeAdvertisement"]) )
        fhandle.write("\tconn_limit = \"{}\"\n".format(obj["connectionLimit"]) )            
        fhandle.write("\tenabled = \"{}\"\n".format(obj["enabled"]) )
        fhandle.write("\tarp = \"{}\"\n".format(obj["arp"]) )
        fhandle.write("\tauto_delete = \"{}\"\n".format(obj["autoDelete"]) )            
        fhandle.write("\ticmp_echo = \"{}\"\n".format(obj["icmpEcho"]) )    
        fhandle.write("\ttraffic_group = \"{}\"\n".format(obj["trafficGroup"]) )

        fhandle.write("}\n\n")

def writeVirtual(fhandle):
    for v in OBJECT_LIBRARY["tm.ltm.virtuals"]:
        fhandle.write("# virtual {} ###################################################\n".format(v["name"]))
        fhandle.write("resource \"bigip_ltm_virtual_server\" \"{}\" ".format(v["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(v["fullPath"]))
        dest = v["destination"].split("/")[-1]
        fhandle.write("\tdestination = \"{}\"\n".format(dest.split(":")[0]))
        fhandle.write("\tport = \"{}\"\n".format(dest.split(":")[-1]))
        
        fhandle.write("\tsource_address_translation = \"{}\"\n".format(v["sourceAddressTranslation"]["type"]))
        fhandle.write("\ttranslate_address = \"{}\"\n".format(v["translateAddress"]))
        fhandle.write("\ttranslate_port = \"{}\"\n".format(v["translatePort"]))
        fhandle.write("\tip_protocol = \"{}\"\n".format(v["ipProtocol"]))
        fhandle.write("\t# profiles = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\t# client_profiles = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\t# server_profiles = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\tsource = \"{}\"\n".format(v["source"]))
        fhandle.write("\t# rules = \"{}\"\n".format("[NOT IMPLEMENTED]"))

        # These have some condidtional as they don't always show up in a config pull    
        fhandle.write("\t# snatpool = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\t# vlans = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\t# vlans_enabled = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\t# vlans_disabled = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\t# persistence_profiles = \"{}\"\n".format("[NOT IMPLEMENTED]"))
        fhandle.write("\t# fallback_persistence_profile = \"{}\"\n".format("[NOT IMPLEMENTED]"))

        fhandle.write("}\n\n")

def writeRoute(fhandle):
    for obj in OBJECT_LIBRARY["tm.net.routes"]:
        fhandle.write("# route {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_route\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tnetwork = \"{}\"\n".format(obj["network"]))
        fhandle.write("\tgw = \"{}\"\n".format(obj["gw"]))

        fhandle.write("}\n\n")

def writeSelfIP(fhandle):
    for obj in OBJECT_LIBRARY["tm.net.selfips"]:
        fhandle.write("# selfip {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_selfip\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tip = \"{}\"\n".format(obj["address"]))
        fhandle.write("\tvlan = \"{}\"\n".format(obj["vlan"]))
        fhandle.write("\ttraffic_group = \"{}\"\n".format(obj["trafficGroup"]))

        fhandle.write("}\n\n")

def writeVlan(fhandle):
    for obj in OBJECT_LIBRARY["tm.net.vlans"]:
        fhandle.write("# vlan {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_net_vlan\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        if "tag" in obj:
            fhandle.write("\ttag = \"{}\"\n".format(obj["tag"]) )

        fhandle.write("\tinterfaces = { \n")
        for iface in obj["interfacesReference"]["members"]:
            fhandle.write("\t\tvlanport = \"{}\"\n".format(iface.fullPath) )
            # BASTARDS!  The nonsense speaks for itself, I wont dignify it with a comment
            if hasattr (iface, 'tagged'):
                fhandle.write("\t\ttagged = \"{}\"\n".format( iface.tagged ))
            else:
                fhandle.write("\t\ttagged = \"{}\"\n".format(not iface.untagged))

        fhandle.write("\t}\n")

        fhandle.write("}\n\n")

def writeProvision(fhandle):
    for obj in OBJECT_LIBRARY["tm.sys.provision"]:
        fhandle.write("# Provision {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_sys_provision\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["fullPath"]) )
        fhandle.write("\tfullPath = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tcpuRatio = \"{}\"\n".format(obj["cpuRatio"]) )            
        fhandle.write("\tdiskRatio = \"{}\"\n".format(obj["diskRatio"]) )
        fhandle.write("\tlevel = \"{}\"\n".format(obj["level"]) )
        fhandle.write("\tmemoryRatio = \"{}\"\n".format(obj["memoryRatio"]) )            

        fhandle.write("}\n\n")

def writeSNMPTraps(fhandle):
    for obj in OBJECT_LIBRARY["tm.sys.snmp.traps_s"]:
        fhandle.write("# SNMP Traps {} ###################################################\n".format(obj["name"]))
        fhandle.write("resource \"bigip_sys_snmp_traps\" \"{}\" ".format(obj["name"]) )
        fhandle.write("{ \n")
        fhandle.write("\tname = \"{}\"\n".format(obj["name"]) )
        fhandle.write("\tcommunity = \"{}\"\n".format(obj["community"]) )
        fhandle.write("\thost = \"{}\"\n".format(obj["host"]) )            
        fhandle.write("\tdescription = \"{}\"\n".format("") )
        fhandle.write("\tport = \"{}\"\n".format(obj["port"]) )

        fhandle.write("}\n\n")

def writeDNS(fhandle):
    for obj in OBJECT_LIBRARY["tm.sys.dns"]:
        fhandle.write("# snatpool {} ###################################################\n".format("DNS"))
        fhandle.write("resource \"bigip_ltm_dns\" \"{}\" ".format("DNS") )
        fhandle.write("{ \n")
        fhandle.write("\tdescription = \"{}\"\n".format("/Common/DNS") )

        fhandle.write("\tname_servers = [")
        for s in obj["nameServers"]:
            fhandle.write("\"{}\",".format(s))
        fhandle.write("]\n")

        fhandle.write("\tnumberof_dots = \"{}\"\n".format(obj["numberOfDots"]) )

        fhandle.write("\tsearch = [")
        for s in obj["search"]:
            fhandle.write("\"{}\",".format(s))
        fhandle.write("]\n")

        fhandle.write("}\n\n")

def writeNTP(fhandle):
    for obj in OBJECT_LIBRARY["tm.sys.ntp"]:
        fhandle.write("# NTP {} ###################################################\n".format("ntp"))
        fhandle.write("resource \"bigip_sys_ntp\" \"{}\" ".format("ntp") )
        fhandle.write("{ \n")
        fhandle.write("\tdescription = \"{}\"\n".format("/Common/ntp") ) # There is no description for NTP

        fhandle.write("\tservers = [")
        for s in obj["servers"]:
            fhandle.write("\"{}\",".format(s))
        fhandle.write("]\n")

        fhandle.write("\ttimezone = \"{}\"\n".format(obj["timezone"]) )            

        fhandle.write("}\n\n")

def writeSNMP(fhandle):
    for obj in OBJECT_LIBRARY["tm.sys.snmp"]:
        fhandle.write("# SNMP {} ###################################################\n".format("SNMP"))
        fhandle.write("resource \"bigip_sys_snmp\" \"{}\" ".format("SNMP") )
        fhandle.write("{ \n")
        fhandle.write("\tsys_contact = \"{}\"\n".format(obj["sysContact"]) )
        fhandle.write("\tsys_location = \"{}\"\n".format(obj["sysLocation"]) )

        fhandle.write("\tallowedaddresses = [")
        for s in obj["allowedAddresses"]:
            fhandle.write("\"{}\",".format(s))
        fhandle.write("]\n")

        fhandle.write("}\n\n")

#################################################################
#   Misc utility Functions
#################################################################
def getLogging():
    FORMAT = '%(asctime)-15s %(levelname)s\tFunc: %(funcName)s():\t%(message)s'
    #FORMAT = '%(message)s'
    logging.basicConfig(format=FORMAT)
    return logging.getLogger('f5-terraform')

def check_ping(address):
    response = os.system("ping -c 1 " + address)

    if response == 0:
        return True

    return False       


#################################################################
#   Entry point
#################################################################
if __name__ == "__main__":
    # Get logging object
    log = getLogging()
    log.setLevel(logging.ERROR)

    main()


