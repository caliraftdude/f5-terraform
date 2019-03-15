import sys
import logging

from f5.bigip import ManagementRoot
import icontrol.exceptions
import f5.sdk_exception

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

OBJECT_LIBRARY = {}


#################################################################
#   Main program
#################################################################
def main():
    # Get logging object
    log = getLogging()
    log.setLevel(logging.INFO)

    # connect to the BigIP
    try:
        MGMT = ManagementRoot("10.1.1.241", "admin", "admin")

    except icontrol.exceptions.iControlUnexpectedHTTPError:
        log.exception("Critical failure during login")
        sys.exit(-1)

    parseObjects(MGMT, log)
    pass

def parseObjects(MGMT, log):
    for OBJ in OBJLIST:
        instance_list = []

        log.info("{} =================================================".format(OBJ.upper()) )

        # Monitors are horribly organized as tm.ltm.monitor is an Organizing Container, which meants that it only has a bunch of reference links to
        # monitor types in it.  This is utterly useless as the api cannot really translate that to anything, so we have to handle monitors
        # differently so that we land on a Collection instead of an Oragnizing Container
        if OBJ == 'tm.ltm.monitor':

            # This will go through some convoluted steps to extract each monitor type and pass its Collection to parseColection
            parse_monitor_oc(MGMT, instance_list, log)

            # Short cut the rest of this function and continue with the loop
            continue

        try:
            collection = eval('MGMT.' + OBJ + '.get_collection()')
        except (f5.sdk_exception.LazyAttributesRequired, AttributeError):
            # Another foul hack.. There is *no* programic way to determine if this is collection or an unnamed resource prior
            # to this call, so if it throws this exception, assume its an unnamed resrouce and use load instead.  To add to the annoyance, 
            # tm.sys.dns throws the LazyAttributes exception while ntp and snmp throw the Attribute error
            collection = eval('MGMT.' + OBJ + '.load()')

        parseCollection(collection, instance_list, log)

        OBJECT_LIBRARY[OBJ] = instance_list


def parseCollection(nodes, instance_list, log):
 
    # Walk through the collection passed to us
    try:

        for node in nodes:
            instance_dict = {}
            # For each item, walk the attributes section.  Since these can be dynamically there or not
            # depending on if configured (we can't rely on a 'none'), its best to go this way then
            # set up a complex expectation of exceptions.  The API should have been from friendly here
            try:
                for key, value in node.attrs.iteritems():
                    parseDictionary(key, value, instance_dict, log)

            except AttributeError:
                # Endpoints like tm.sys.provision drop straight into a resource, so we will throw an attr exception.
                # check for this first and assume that we have a dictionary of key-value pairs already (bad assumption? monitors would fall
                # under this case as well so to make this truely genereic you would need to determine what sort of end point you landed
                # on and there is no way to determine that.
                for key, value in node.iteritems():
                    parseDictionary(key, value, instance_dict, log)

            instance_list.append(instance_dict)

    except TypeError:
        instance_dict = {}

        # Objects like tm.sys.dns have no list but, so the iteration will throw, in this case just walk the attribute list
        # note we just use the nodes object.. subtle if you C&P this out of here.
        for key, value in nodes.attrs.iteritems():
            parseDictionary(key, value, instance_dict, log)
        
        instance_list.append(instance_dict)


def parseDictionary(key, value, instance_dict, log):
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

        for k, v in value.iteritems():
            log.info('\t\t{}: {}'.format(k, v))


def parse_monitor_oc(MGMT, instance_list, log):
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
        parseCollection(collection, instance_list, log)

        OBJECT_LIBRARY[label] = instance_list

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
    main()
