#!/usr/bin/env python

# Copyright 2014: Lithium Technologies, Inc
# License: Apache License v2.0
# Author(s):
#   - Paul Allen (paul.allen@lithium.com)
# Example Usage:
#   - ./ha-nat.py --log-file /var/log/ha-nat.log --monitor-interval 15 --private-subnets "subnet-30fe0b55,subnet-eeb782a8"
#
import boto
import boto.ec2
import datetime
import os
import sys
from optparse import OptionParser
from boto.vpc import VPCConnection
import subprocess
import socket
import time

version = "0.1.4"

## globals for caching
MY_AZ = None
MY_VPC_ID = None
INSTANCE_ID = None
MY_SUBNETS = None
MY_ROUTE_TABLES = None

def parseArgs():
    parser = OptionParser("usage: %prog [options]")
    parser.add_option("--debug",             dest="debug",          default=False, action="store_true",     help="Whether or not to run in debug mode [default: %default]")
    parser.add_option("--version",           dest="version",        default=False, action="store_true",     help="Display the version and exit")
    parser.add_option("--env",               dest="env",            default="dev",                          help="The environment in which this is running")
    parser.add_option("--monitor-interval",  dest="monitorInterval",default="300",                          help="The frequency in seconds of which to check the routes [default: %default]")
    parser.add_option("--private-subnets",   dest="privateSubnets", default="",                             help="A CSV of private subnet ids to ensure a 0.0.0.0/0 route exists from each subnet to the NAT instance")
    parser.add_option("--log-file",          dest="logFile",        default="/var/log/ha-nat.log",          help="The log file in which to dump debug information [default: %default]")
    return parser.parse_args()

def log(statement):
    statement = str(statement)
    if options.logFile is None:
        return
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
    tag = "env:%s,region:%s,vpc:%s,az:%s" % (options.env, getRegion(), getMyVPCId(), getAvailabilityZone())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # event datagram is as follows
    # _e{title.length,text.length}:title|text|d:date_happened|h:hostname|p:priority|t:alert_type|#tag1,tag2
    datagram = u'_e{%d,%d}:%s|%s|#%s' % (len(title), len(text), title, text, tag)
    log("event datagram %s" % datagram)
    # Send event down to the local dogstatsd
    if options.debug:
        log("sending event to datadog => " + datagram)
    else:
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

def disableSourceDestChecks():
    EC2.modify_instance_attribute(getInstanceId(), "sourceDestCheck", False)

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

def replaceIfWrongAZ():
    log("replaceIfWrongAZ | checking getAvailabilityZone(): %s" % getAvailabilityZone())
    ## find subnet(s) in my AZ
    for subnet in getMySubnets():
        log("replaceIfWrongAZ | checking subnet: %s" % subnet.id)
        ## find routes with instances
        for route_table in getMyRouteTables(subnet):
            log("replaceIfWrongAZ | checking route table: %s" % route_table.id)
            if route_table.id == None:
                continue
            for route in route_table.routes:
                log("replaceIfWrongAZ | checking route: %s | %s" % (route.destination_cidr_block, route.instance_id))
                if route.instance_id == None:
                    continue
                if route.destination_cidr_block != '0.0.0.0/0':
                    continue
                if route.instance_id == None or route.instance_id == "":
                    continue
                ## check the AZ of the instances
                for instance in EC2.get_only_instances(instance_ids=[route.instance_id]):
                    if instance.placement != getAvailabilityZone():
                        ## wrong zone
                        ## if the AZ of the instance is different than ours and the route table, replace it
                        log('incorrect az - replacing route')
                        if not options.debug:
                            VPC.replace_route(route_table_id = route_table.id,
                                              destination_cidr_block = route.destination_cidr_block,
                                              gateway_id = route.gateway_id,
                                              instance_id = getInstanceId())
                            sendEvent("Taking over route (preferred AZ)", "instance [%s] is assinging cidr [%s] to itself on route table [%s]" % (getInstanceId(), route.destination_cidr_block, route_table.id), options)
                        else:
                            log('skipped VPC.replace_route due to debug flag')

                    else:
                        ## correct zone
                        ## if the AZ of the instance is the same, do nothing
                        log('correct az - not replacing the route')

def ensureSubnetRoutes():
    for subnet in options.privateSubnets.split(','):
        rt_filters = [['vpc-id', getMyVPCId()], ['association.subnet-id', subnet]]
        route_tables = VPC.get_all_route_tables(filters=rt_filters)
        for route_table in route_tables:
            if route_table.id == None:
                continue
            natRouteExists = False
            for route in route_table.routes:
                if route.destination_cidr_block == '0.0.0.0/0':
                    natRouteExists = True
                    break
            if not natRouteExists:
                ## we create the route in a try/catch because during a race condition
                ## AWS will not allow duplicate route entries. This exception simply
                ## means the work has already been done
                try:
                    log("creating route route_table_id = %s, destination_cidr_block = '0.0.0.0/0', instance_id = %s" % (route_table.id, getInstanceId()))
                    if not options.debug:
                        VPC.create_route(route_table_id = route_table.id,
                                         destination_cidr_block = '0.0.0.0/0',
                                         instance_id = getInstanceId())
                        sendEvent("Missing Routes", "instance [%s] is creating routes for cidr [0.0.0.0/.0] to itself on route table [%s]" % (getInstanceId(), route_table.id), options)

                    else:
                        log('skipped VPC.create_route due to debug flag')

                except Exception as e:
                    log(str(e))

def main():
    ## this should do the following
    ##   1) ensure a private subnet route exists pointing to 0.0.0.0/0
    ##   2) ensure source/destination checks are disabled
    ##   3) if there is a blackhole in replace it with this instnace
    ##   4) if there is no blackhole in this AZ, replace only if the registered instance
    ##      is NOT in this AZ
    for route_table in findBlackholes():
        log("main | checking route table: %s" % route_table.id)
        if route_table.id == None:
            continue
        for route in route_table.routes:
            log("main | checking route: %s | %s" % (route.destination_cidr_block, route.instance_id))
            if not route.state == 'blackhole':
                continue
            if route.destination_cidr_block != '0.0.0.0/0':
                continue
            log('main | found a black hole - taking the route over')
            if not options.debug:
                VPC.replace_route(route_table_id = route_table.id,
                                  destination_cidr_block = route.destination_cidr_block,
                                  gateway_id = route.gateway_id,
                                  instance_id = getInstanceId())
                sendEvent("Found a black hole", "instance [%s] is assinging cidr [%s] to itself on route table [%s]" % (getInstanceId(), route.destination_cidr_block, route_table.id), options)
            else:
                log('skipped VPC.replace_route due to debug flag')
    replaceIfWrongAZ()                         
   
(options, args) = parseArgs()

if options.version:
    print(version)
    sys.exit(0)

EC2 = boto.ec2.connect_to_region(getRegion())
VPC = boto.vpc.connect_to_region(getRegion())

## these only need to run once
log("disabling source/destination checks")
disableSourceDestChecks()
if len(options.privateSubnets) > 0 and len(options.privateSubnets.split(',')) > 0:
    log("ensuring private subnet routes exist")
    ensureSubnetRoutes()

while True:
    try:
      main()
    except Exception as e:
      log(str(e))
    log("sleeping %d before rechecking" % (int(options.monitorInterval)))
    time.sleep(int(options.monitorInterval))
