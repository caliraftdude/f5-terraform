#!/usr/bin/python
import sys
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


    # global USERNAME
    # global PASSWORD

    # USERNAME = getpass.getpass(prompt="Username:\t")
    # PASSWORD = getpass.getpass(prompt="Password:\t")

    # connect to the BigIP
    try:
        MGMT = ManagementRoot("10.1.1.241", "admin", "admin")

    except icontrol.exceptions.iControlUnexpectedHTTPError:
        log.exception("Critical failure during login")
        sys.exit(-1)

    parseObjects(MGMT)



    # This should be re-written to break this up into a bunch of different files..  probably a file per object-type
    # It may also make sense to put into its own directory and put it into exception handling..
    with open("bigip.tf", "w") as fhandle:
        writeProvider(fhandle)
        fhandle.flush()
    
    with open("tm.ltm.pools.tf", "w") as fhandle:
        writePool(fhandle)
        fhandle.flush()

    with open("tm.ltm.virtuals.tf", "w") as fhandle:
        writeVirtual(fhandle)
        fhandle.flush()

def parseObjects(MGMT):
    for OBJ in OBJLIST:
        instance_list = []

        log.info("{} =================================================".format(OBJ.upper()) )

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
    if type(value) is unicode:
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
                    members_list.append(member.name)

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

def writeMonitor(fhandle):
    pass

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

            # yet another hassle to unwind, search through the nodes so we can find the full path
            # and then munge together <full path>:<port>
            ip_address = node.split(":")[0]
            port = node.split(":")[1]

            for i in OBJECT_LIBRARY["tm.ltm.nodes"]:
                if i["address"] == ip_address:
                    fullpath = i["fullPath"]
                    break

            fhandle.write("\tnode = \"{}\"\n".format(fullpath + ":" + port))
            fhandle.write("}\n")

        fhandle.write("\n\n")

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


#################################################################
#   Misc utility Functions
#################################################################
def getLogging():
    FORMAT = '%(asctime)-15s %(levelname)s\tFunc: %(funcName)s():\t%(message)s'
    #FORMAT = '%(message)s'
    logging.basicConfig(format=FORMAT)
    return logging.getLogger('f5-terraform')


#################################################################
#   Entry point
#################################################################
if __name__ == "__main__":
    # Get logging object
    log = getLogging()
    log.setLevel(logging.INFO)

    main()
