# Highly Available NAT cluster

I'm sorry to say this probably won't work for you, this is a customized fork that meets specific
requirements for a test environment.

It can be used on a single NAT instance in a VPC, or in an HA configuration with 1 NAT per AZ in the VPC.

#### Important
It should be noted that the cluster itself is highly avaiable, but not so in a single AZ. When one
NAT is lost, one of the others will take over until AWS AutoScale group instance replacement occurs.
From the moment one is lost, NATing from that AZ will be down until one of the others in the cluster
takes over the routing. This happens quickly, so even for the affected AZ a lost NAT will have little
affect. The other AZ's will remain unaffected and thus the "system" is still up.

#### IAM Requirements
There are a few requirements for this to run correctly. Firstly, you must utilize the NAT AMI provided
by Amazon AWS. Should you make a mistake and run on standard Amazon Linux, the nat will simply not work.
Secondly, the nat instance must run within an IAM role which must have permissions to modify vairous VPC
objects such as route tables. Here is the basic IAM role permissions set necessary for the HA-NAT. Resouce
is called out as [ "arn:aws:ec2:::*" ] simply because the vpc object IDS are unknown:
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1436895015000",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeAvailabilityZones",
        "ec2:ModifyInstanceAttribute",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeRegions",
        "ec2:ModifyInstanceAttribute",
        "ec2:ReplaceRoute",
        "ec2:CreateRoute",
        "ec2:ReplaceRouteTableAssociation",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:AssociateAddress",
        "ec2:DescribeAddresses",
        "ec2:DisassociateAddress",
        "ec2:DescribeInstances"
      ],
      "Resource": [
        "*"
      ],
      "Condition": {
        "ForAllValues:StringEquals": {
          "ec2:ResourceTag/aws:autoscaling:groupName": "<autoscaling group name>"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeRouteTables"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Details
The basic idea is as follows:
  1. The NAT instance running this script will operate only on its own VPC.
  1. The NAT instance will operate only on 0.0.0.0/0 routes, leaving other untouched.
  1. If 0.0.0.0/0 routes do not exist on the supplied private subnets, it will create them
  1. If there is a 'blackhole' anywhere in the 0.0.0.0/0 routes on any routetable in the VPC, 
     the NAT instance will insert itself into that route to eliminate the blackhole
  1. If there are not any blackholes, it will begin to check any route-table associations for
     the subnets in the Availability-Zone (AZ) in which this instance is currently in.
     For example, if this instance comes up in us-east-1a, assuming a public and private
     subnet in each AZ, the instance would operate on the private-1a and public-1a subnets (as
     there is really no public/private distinction).
  1. If the NAT assigned to a route table is in a different AZ than the subnet (i.e. the 
     NAT is in 1b, but the subnets are 1a) this instance will prefer itself and replace the
     existing NAT instance in the route.

the options are straightforward.
  1. --version
    * display the current version of the rpm
  1. --log-file </log/file/location>
    * where to log output
  1. --monitor-interval <how often to check the routes in seconds>
    * i.e. --monitor-interval 20 ##To check every 20 seconds
  1. --private-subnets <comma sperated list of private subnets in the vpc>
    * i.e. --private-subnets "subnet-12345678,subnet-abcdefgh,subnet-87654321" ##To check every 1 minute
  1. --env <environment>
    * i.e. --env "dev"
  1. --eips <CSV of EIPs to assign to the NATs>
    * i.e. --eips 1.2.3.4,10.20.30.40,9.8.7.6
  1. --create-eips <flag to indicate the nat is allowed to create eips if they are missing>
    * i.e. --create-eips with no --eips will simply use/create eips as needed. if they are deleted, new ones will be created and used
i.e.

  * ./ha-nat.py --log-file "/var/log/ha-nat" --monitor-interval 20 --env "dev" --private-subnets "subnet-12345678,subnet-abcdefgh"
