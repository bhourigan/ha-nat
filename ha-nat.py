#!/usr/bin/env python

# Copyright 2014: Lithium Technologies, Inc
# License: Apache License v2.0
# Author(s):
#   - Paul Allen (paul.allen@lithium.com)
# Example Usage:
#   - ./ha-nat.py --log-file /var/log/ha-nat.log --monitor-interval 15 --private-subnets "subnet-30fe0b55,subnet-eeb782a8"
#   - ./ha-nat.py --log-file /var/log/ha-nat.log --monitor-interval 15 --private-subnets "subnet-30fe0b55,subnet-eeb782a8" --eips "1.2.3.4,10.20.30.40,99.88.77.66"
#   - ./ha-nat.py --log-file /var/log/ha-nat.log --monitor-interval 15 --private-subnets "subnet-30fe0b55,subnet-eeb782a8" --create-eips
#
import boto
import boto.ec2
from boto.exception import EC2ResponseError
import datetime
import os
import sys
from optparse import OptionParser
from boto.vpc import VPCConnection
import subprocess
import socket
import time
import syslog

version = "2.0.0"

## globals for caching
MY_AZ = None
MY_VPC_ID = None
INSTANCE_ID = None
MY_SUBNETS = None
MY_ROUTE_TABLES = None

def parseArgs():
    parser = OptionParser("usage: %prog [options]")
    parser.add_option("--debug",             dest="debug",          default=False, action="store_true",     help="Whether or not to run in debug mode [default: %default]")
    parser.add_option("--quiet",             dest="quiet",          default=False, action="store_true",     help="Whether or not to be quiet [default: %default]")
    parser.add_option("--destination-cidr",  dest="destCidr",       default="0.0.0.0/0",                    help="Destination CIDR block for route table entries")
    parser.add_option("--eips",              dest="eips",           default=None,                           help="A CSV of EIPs to assign to the NATs.")
    parser.add_option("--eni",               dest="eni",            default=None,                           help="The elastic network interface to route to")
    parser.add_option("--env",               dest="env",            default="dev",                          help="The environment in which this is running")
    parser.add_option("--log-file",          dest="logFile",        default="/var/log/ha-nat.log",          help="The log file in which to dump debug information [default: %default]")
    parser.add_option("--monitor-interval",  dest="monitorInterval",default=None,                           help="The frequency in seconds of which to check the routes [default: %default]")
    parser.add_option("--subnets",           dest="subnets",        default="",                             help="A CSV of subnet ids to ensure a route exists from each subnet to the NAT instance or network interface")
    parser.add_option("--version",           dest="version",        default=False, action="store_true",     help="Display the version and exit")
    return parser.parse_args()

def log(statement, event=False):
    statement = str(statement)

    # Always print event related messages, even when --quiet is specified
    if options.quiet is True and event is False:
        return

    # Always log to syslog
    syslog.openlog("ha-nat")
    syslog.syslog(statement)
    syslog.closelog()

    # Always print to stdout
    print statement

    # Log to a file if one has been specified
    if options.logFile is not None:
        if not os.path.exists(os.path.dirname(options.logFile)):
            os.makedirs(os.path.dirname(options.logFile))

        logFile = open(options.logFile, 'a')
        ts = datetime.datetime.now()
        isFirst = True
        for line in statement.split("\n"):
            if isFirst:
                logFile.write("%s - %s\n" % (ts, line))
                isFirst = False
            else:
                logFile.write("%s -    %s\n" % (ts, line))
        logFile.close()

def sendEvent(title, text, options):
    # Log events in english only if we're in quiet mode
    if options.quiet is True:
        log(statement="%s: %s" % (title, text), event=True)

    if options.debug is True:
        return

    # Build tags and open a dgram socket
    tag = "env:%s,region:%s,vpc:%s,az:%s" % (options.env, getRegion(), getMyVPCId(), getAvailabilityZone())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # event datagram is as follows
    # _e{title.length,text.length}:title|text|d:date_happened|h:hostname|p:priority|t:alert_type|#tag1,tag2
    datagram = u'_e{%d,%d}:%s|%s|#%s' % (len(title), len(text), title, text, tag)
    log("event datagram %s" % datagram)

    # Send event down to the local dogstatsd
    sock.sendto(datagram, ("127.0.0.1", 8125))

def cmd_output(args, **kwds):
    ## this function will run a command on the OS and return the result
    kwds.setdefault("stdout", subprocess.PIPE)
    kwds.setdefault("stderr", subprocess.STDOUT)
    proc = subprocess.Popen(args, **kwds)
    return proc.communicate()[0]

def metaData(dataPath):
    ## using 169.254.169.254 instead of 'instance-data' because some people
    ## like to modify their dhcp tables...
    return cmd_output(["curl", "-sL", "169.254.169.254/latest/meta-data/" + dataPath])

def getAvailabilityZone():
    ## cached
    global MY_AZ
    if MY_AZ is None:
        MY_AZ = metaData("placement/availability-zone")
    return MY_AZ

def getRegion():
  return getAvailabilityZone()[:-1]

def getInstanceId():
    ## cached
    global INSTANCE_ID
    if INSTANCE_ID == None:
        INSTANCE_ID = metaData("instance-id")
    return INSTANCE_ID

def findBlackholes():
    ## don't cache this value as we need to keep checking
    myFilters = [['vpc-id', getMyVPCId()], ['route.state', 'blackhole']]
    return VPC.get_all_route_tables(filters=myFilters)

def touch(path):
    with open(path, 'a'):
        os.utime(path, None)

def disableSourceDestChecks():
    if options.eni != None and options.eni != "":
        interface_path = "/tmp/" + options.eni

        if not os.path.isfile(interface_path):
            EC2.modify_network_interface_attribute(options.eni, "sourceDestCheck", False)
            log("disableSourceDestChecks | disabling sourceDestCheck on %s" % options.eni)
        else:
            log("disableSourceDestChecks | sourceDestCheck already disabled on %s" % options.eni)

    else:
        interface_path = "/tmp/" + getInstanceId()
        if not os.path.isfile(interface_path):
            EC2.modify_instance_attribute(getInstanceId(), "sourceDestCheck", False)
            log("disableSourceDestChecks | disabling sourceDestCheck on %s" % getInstanceId())
        else:
            log("disableSourceDestChecks | sourceDestCheck already disabled on %s" % getInstanceId())

    touch(interface_path)

def getMySubnets():
    ## cached
    global MY_SUBNETS
    if MY_SUBNETS == None:
        az_subnet_filters = [['availability-zone', getAvailabilityZone()],['vpc-id', getMyVPCId()]]
        MY_SUBNETS = VPC.get_all_subnets(filters=az_subnet_filters)
    return MY_SUBNETS

def getMyRouteTables(subnet):
    ## this cannot be cached beacuse we need to keep checking the route tables
    rt_filters = [['vpc-id', getMyVPCId()], ['association.subnet-id', subnet.id]]
    return VPC.get_all_route_tables(filters=rt_filters)

def getMyVPCId():
    ## cached
    global MY_VPC_ID
    if MY_VPC_ID == None:
        MY_VPC_ID = getMe().vpc_id
    return MY_VPC_ID

def getMe():
    ## don't cache this as our instance attributes can change
    return EC2.get_only_instances(instance_ids=[getInstanceId()])[0]

def ensureSubnetRoutes():
    for subnet in options.subnets.split(','):
        log("ensureSubnetRoutes | checking subnet: %s" % subnet)
        rt_filters = [['vpc-id', getMyVPCId()], ['association.subnet-id', subnet]]
        route_tables = VPC.get_all_route_tables(filters=rt_filters)

        for route_table in route_tables:
            log("ensureSubnetRoutes | checking route table: %s" % route_table.id)
            if route_table.id == None:
                continue

            natRouteExists = False
            natRouteCorrectTarget = False

            for route in route_table.routes:
                log("ensureSubnetRoutes | checking route: %s | instance %s | interface %s | gateway %s" % (route.destination_cidr_block, route.instance_id, route.interface_id, route.gateway_id))

                if route.instance_id == None and route.gateway_id == None:
                    continue

                if route.destination_cidr_block == options.destCidr:
                    if options.eni != None and options.eni != "":
                        if route.gateway_id == options.eni:
                            natRouteCorrectTarget = True
                        else:
                            if route.instance_id == getInstanceId():
                                natRouteCorrectTarget = True
                    natRouteExists = True
                    break

            if natRouteExists and not natRouteCorrectTarget:
                log('ensureSubnetRoutes | incorrect route target - replacing route')

                if not options.debug:
                    if options.eni != None and options.eni != "":
                        VPC.replace_route(route_table_id = route_table.id,
                            destination_cidr_block = route.destination_cidr_block,
                            interface_id = options.eni)

                        sendEvent("Replaced route (incorrect target)", "instance [%s] is assinging cidr [%s] to [%s] on route table [%s]" % (getInstanceId(), route.destination_cidr_block, options.eni, route_table.id), options)
                    else:
                        VPC.replace_route(route_table_id = route_table.id,
                            destination_cidr_block = route.destination_cidr_block,
                            gateway_id = route.gateway_id,
                            instance_id = getInstanceId())

                        sendEvent("Replaced route (incorrect target)", "instance [%s] is assinging cidr [%s] to [%s] on route table [%s]" % (getInstanceId(), route.destination_cidr_block, getInstanceId(), route_table.id), options)
                else:
                    log('ensureSubnetRoutes | Skipped VPC.replace_route due to debug flag')

            if not natRouteExists:
                ## we create the route in a try/catch because during a race condition
                ## AWS will not allow duplicate route entries. This exception simply
                ## means the work has already been done
                try:
                    if options.eni != None and options.eni != "":
                        log("ensureSubnetRoutes | creating route route_table_id = %s, destination_cidr_block = %s, interface_id = %s" % (route_table.id, options.destCidr, options.eni))
                    else:
                        log("ensureSubnetRoutes | creating route route_table_id = %s, destination_cidr_block = %s, instance_id = %s" % (route_table.id, options.destCidr, getInstanceId()))

                    if not options.debug:
                        if options.eni != None and options.eni != "":
                            VPC.create_route(route_table_id = route_table.id,
                                             destination_cidr_block = options.destCidr,
                                             interface_id = options.eni)
                            sendEvent("Creating route", "instance [%s] is creating routes for cidr [%s] to [%s] on route table [%s]" % (getInstanceId(), options.destCidr, options.eni, route_table.id), options)
                        else:
                            VPC.create_route(route_table_id = route_table.id,
                                             destination_cidr_block = options.destCidr,
                                             instance_id = getInstanceId())
                            sendEvent("Creating route", "instance [%s] is creating routes for cidr [%s] to [%s] on route table [%s]" % (getInstanceId(), options.destCidr, getInstanceId(), route_table.id), options)
                    else:
                        log('ensureSubnetRoutes | Skipped VPC.create_route due to debug flag')

                except Exception as e:
                    log(str(e))

def replaceBlackHoles():
    for route_table in findBlackholes():
        log("replaceBlackHoles | checking route table: %s" % route_table.id)
        if route_table.id == None:
            continue
        for route in route_table.routes:
            log("replaceBlackHoles | checking route: %s | instance %s | interface %s | gateway %s" % (route.destination_cidr_block, route.instance_id, route.interface_id, route.gateway_id))
            if not route.state == 'blackhole':
                continue
            if route.destination_cidr_block != options.destCidr:
                continue

            log('replaceBlackHoles | found a black hole - taking the route over')
            if not options.debug:
                if options.eni != None and options.eni != "":
                    VPC.replace_route(route_table_id = route_table.id,
                                      destination_cidr_block = route.destination_cidr_block,
                                      interface_id = options.eni)
                    sendEvent("Replacing blackhole", "instance [%s] is assinging cidr [%s] to [%s] on route table [%s]" % (getInstanceId(), route.destination_cidr_block, options.eni, route_table.id), options)
                else:
                    VPC.replace_route(route_table_id = route_table.id,
                                      destination_cidr_block = route.destination_cidr_block,
                                      gateway_id = route.gateway_id,
                                      instance_id = getInstanceId())
                    sendEvent("Replacing blackhole", "instance [%s] is assinging cidr [%s] to [%s] on route table [%s]" % (getInstanceId(), route.destination_cidr_block, getInstanceId(), route_table.id), options)
            else:
                log('replaceBlackHoles | Skipped VPC.replace_route due to debug flag')

def associateElasticIps():
    log("associateElasticIps | associating elastic IPs [%s]" % options.eips)

    ## check if we have an EIP assigned to us
    filters = {'instance-id': getInstanceId()}
    addresses = EC2.get_all_addresses(filters = filters)
    have_eip = False

    # Bug: check for addresses that are associated, but not specified as --eips and disassociate them
    if not addresses:
        ## we don't have any EIPs
        log("associateElasticIps | no EIPs are associated with this instance")

        for eip in options.eips.split(','):
            if eip == "":
                continue

            log("associateElasticIps | checking that %s belongs to our account" % eip)
            try:
                address = EC2.get_all_addresses(addresses = [eip])[0]
                log("associateElasticIps | confirmed that eip [%s] belongs to our account" % (address))
            except EC2ResponseError:
                log("associateElasticIps | ERROR: address not found in account %s" % eip)
                continue

            ## we only care about addresses that are not associated
            if address.association_id:
                continue

            if address.public_ip == eip:
                log("associateElasticIps | associating eip [%s] to this instance [%s]" % (eip, getInstanceId()))

                if options.eni != None and options.eni != "":
                    EC2.associate_address(network_interface_id = options.eni, public_ip = eip, allocation_id = address.allocation_id)
                    sendEvent("Associated EIP", "instance [%s] is associating eip [%s] to interface [%s]" % (getInstanceId(), eip, options.eni), options)
                else:
                   	EC2.associate_address(instance_id = getInstanceId(), public_ip = eip, allocation_id = address.allocation_id)
                        sendEvent("Associated EIP", "instance [%s] is associating eip [%s]" % (getInstanceId(), eip), options)
                have_eip = True
    else:
        log("associateElasticIps | elastic addresses already associated: %s" % addresses)
        have_eip = True

    if have_eip == False:
        sendEvent("Cannot assign EIP", "instance [%s] is unable to assign an eip although asked to do so" % (getInstanceId()), options)
        raise Exception('Unable to assign requested EIP - not continuing')

def main():
    ## this should do the following
    ##   1) if eips are specified we call associateElasticIps()
    ##      a) check to see if we already have any associated elastic IPs
    ##      b) if not, associate the specified addresses
    ##   2) ensure that the route tables associated with the specified subnets have a route for destCidr to
    ##      either a eni or this instance id
    ##   3) search for blackholes in the route tables associated with the specified subnets
    ##     a) if there is a blackhole in replace it with a eni or instnace id
    if options.eips != None and options.eips != "":
        log("main | calling associateElasticIps()")
        associateElasticIps();

    if options.subnets != None and options.subnets != "":
        log("main | calling ensureSubnetRoutes()")
        ensureSubnetRoutes()

        log("main | calling replaceBlackHoles()")
        replaceBlackHoles()

(options, args) = parseArgs()

if options.version:
    print(version)
    sys.exit(0)

EC2 = boto.ec2.connect_to_region(getRegion())
VPC = boto.vpc.connect_to_region(getRegion())

## these only need to run once
log("core | disabling source/destination checks")
disableSourceDestChecks()

while True:
    try:
        main()
    except Exception as e:
        log("core | ERROR: %s" % str(e))
        if options.monitorInterval == None:
            sys.exit(1)

    if options.monitorInterval == None:
        sys.exit(0)

    log("sleeping %d before rechecking" % (int(options.monitorInterval)))
    time.sleep(int(options.monitorInterval))
