import difflib
import pexpect
import re

user     = ""
password = ""
device1  = ""
device2  = ""

class Acl:
    aclName  = ""
    action   = ""
    remark   = ""
    extended = ""
    aclType  = ""
    
    def __str__(self):
        result = "access-list " + self.aclName + " "
        
        if self.aclType == "extended":
            result += "extended " + self.action + " " + self.extended
        elif self.aclType == "remark":
            result += "remark " + self.remark
        else:
            result = "~Error: action: " + self.action + " remark: " + self.remark + " extended: " + self.extended + " aclType: " + self.aclType
            
        return result

class Config:
    acls         = []
    netObjects   = []
    objectGroups = []    
    
    def __str__(self):
        result = ""
        
        for netObj in self.netObjects:
            result += netObj.__str__() + "\n"

        for objGrp in self.objectGroups:
            result += objGrp.__str__() + "\n"

        for acl in self.acls:
            result += acl.__str__() + "\n"

        return result
    
class Host:
    ip = "0.0.0.0"

    def __str__(self):
        return " host " + self.ip;

class Subnet:
    ip   = "0.0.0.0"
    mask = "255.255.255.255"

    def __str__(self):
        return " subnet " + self.ip + " " + self.mask;    

class Range:
    ipStart = "0.0.0.0"
    ipEnd   = "0.0.0.0"

    def __str__(self):
        return " range " + self.ipStart + " " + self.ipEnd;    

class NetworkObject:
    name    = ""
    hosts   = []
    subnets = []
    ranges  = []

    def __str__(self):
        result = "object network " + self.name + "\n"

        for host in self.hosts:
            result += host.__str__() + "\n"

        for subnet in self.subnets:
            result += subnet.__str__() + "\n"

        for rng in self.ranges:
            result += rng.__str__() + "\n"
        
        return result

class NetworkObjectGroup:
    name        = ""
    groupType   = ""
    serviceType = ""
    typeList    = []
    valueList   = []

    def __str__(self):
        if self.groupType == "icmp-type" or self.groupType == "protocol" : 
            result = "object-group " + self.groupType + " " + self.name+ "\n"

            for index in range(len(self.typeList)):
                result += " " + self.typeList[index] + " " + self.valueList[index] + "\n"
        elif self.groupType == "service":
            result = "object-group " + self.groupType + " " + self.name + " " + self.serviceType + "\n"

            for index in range(len(self.typeList)):
                result += " " + self.typeList[index] + " eq " + self.valueList[index] + "\n"            
        return result
    
def connectSSH (host):
    
    #ssh into host
    child = pexpect.spawn ('ssh ' + user + '@' + device1)
    child.expect ('.*assword:.*')
    child.sendline (password)

    #enable mode
    child.expect ('.*>.*')
    child.sendline ('enable')
    child.expect ('.*assword:.*')
    child.sendline (password)

    #change page length to '0 - no limit'
    child.sendline ('terminal pager 0')

    #get running config
    child.sendline ('show run')
    child.expect ('.*: end.*')
    config = child.after

    child.sendline('exit')
    child.close() # close ssh
    
    return config

def parseAccessLists (config):
    acls  = []
    eList = config.split()
    index = 0

    while index < len(eList):
        try:
            newAcl = Acl()
            newAcl.remark = ""
            newAcl.action = ""
            
            index   = eList.index("access-list", index)
            index  += 1
            newAcl.aclName = eList[index]
            index  += 1
            newAcl.aclType = eList[index]

            if newAcl.aclType == "ethertype":
                print "~Ethertype"
            elif newAcl.aclType == "extended":
                index  += 1

                try:
                    endIndex    = eList.index("access-list", index)
                except ValueError:
                    endIndex    = len(eList)
                    
                newAcl.action   = eList[index]
                newAcl.extended = " ".join(eList[index:endIndex])
            elif newAcl.aclType == "remark":
                try:
                    endIndex    = eList.index("access-list", index)
                except ValueError:
                    endIndex    = len(eList)
                    
                index          += 1
                newAcl.remark   = " ".join(eList[index:endIndex])
                newAcl.extended = " "
            else:
                print "~Unknown ACL Type"

            acls.append(newAcl)
            
        except ValueError:
            print "~End of ACL List"
            break

    
    return acls

def parseConfig (config):
    newConfig = Config()
    aclStart  = config.index("access-list")
    start     = config.index("object")
    objStart  = config.index("object-group")

    newConfig.acls         = []
    newConfig.netObjects   = []
    newConfig.objectGroups = []
    
    #Read Object networks
    while start < objStart: 
        try:
            end   = config.index("object network", (start + 6))
            acl   = config[start:end]
            start = end

            newConfig.netObjects.append(parseNetObject(acl))
  
        except ValueError:
            start = objStart

    #Read Object-groups
    while start < aclStart: 
        try:
            end   = config.index("object-group", (start + 12))
            acl   = config[start:end]
            start = end

            newConfig.objectGroups.append(parseObjectGroup(acl))
  
        except ValueError:
            print "Error"
            start = aclStart

    #Read Access Lists
    aclEnd  = config.index("!", aclStart)
    aclText = config[aclStart:aclEnd]

    newConfig.acls = parseAccessLists(aclText)
    
    return newConfig;

def parseNetObject (objText):
    newObject = NetworkObject()
    newObject.hosts   = []
    newObject.subnets = []
    newObject.ranges  = []
    
    #Parse Object Name
    start = objText.index("network") + 7
    end   = objText.index("\n", start)
    newObject.name = objText[start:end]
    start = end + 1

    end   = objText.index("\n", start)
    entry = objText[start:end]
    start = end + 1
    eList = entry.split()

    #Parse Subnets
    if eList[0] == "subnet":
        newSubnet      = Subnet()
        newSubnet.ip   = eList[1]
        newSubnet.mask = eList[2]
        newObject.subnets.append(newSubnet)
        
    #Parse Hosts
    if eList[0] == "host":
        newHost = Host()
        newHost.ip = eList[1]
        newObject.hosts.append(newHost)
        
    #Parse Ranges
    if eList[0] == "range":
        newRange = Range()
        newRange.ipStart = eList[1]
        newRange.ipEnd   = eList[2]
        newObject.ranges.append(newRange)
        
    return newObject;

def parseObjectGroup (objText):
    eList = objText.split()
    
    if eList[1] == "network":
        newObject = NetworkObject()
        newObject.hosts   = []
        newObject.subnets = []
        newObject.ranges  = []
        newObject.name    = eList[2]
        index             = 4

        while index < len(eList):
            if eList[index] == "host":
                index += 1
                newHost = Host()
                newHost.ip = eList[index]
                newObject.hosts.append(newHost)
            else:
                newSubnet      = Subnet()
                newSubnet.ip   = eList[index]
                index += 1
                newSubnet.mask = eList[index]
                newObject.subnets.append(newSubnet)
                
            if (index + 2) < (len(eList) - 1):
                index += 2
            else:
                break
                
        return newObject
    elif eList[1] == "icmp-type":
        newObject           = NetworkObjectGroup()
        newObject.typeList  = []
        newObject.valueList = []    
        newObject.groupType = "icmp-type"
        newObject.name      = eList[2]
        index = 3

        while index < len(eList):
            if eList[index] == "icmp-object":
                index += 1
                newObject.typeList.append("icmp-object")
                newObject.valueList.append(eList[index])

            if (index + 1) < (len(eList) - 1):
                index += 1
            else:
                break

        return newObject
    elif eList[1] == "protocol":
        newObject             = NetworkObjectGroup()
        newObject.typeList    = []
        newObject.valueList   = []            
        newObject.name        = eList[2]
        newObject.groupType   = "protocol"
        index                 = 3

        while index < len(eList):
            if eList[index] == "protocol-object":
                index += 1
                newObject.typeList.append("protocol-object")
                newObject.valueList.append(eList[index])

            if (index + 1) < (len(eList) - 1):
                index += 1
            else:
                break

        return newObject        
    elif eList[1] == "service":
        newObject             = NetworkObjectGroup()
        newObject.typeList    = []
        newObject.valueList   = []            
        newObject.name        = eList[2]
        newObject.groupType   = "service"
        newObject.serviceType = eList[3]
        index                 = 4

        while index < len(eList):
            if eList[index] == "port-object":
                index += 2
                newObject.typeList.append("port-object")
                newObject.valueList.append(eList[index])

            if (index + 1) < (len(eList) - 1):
                index += 1
            else:
                break

        return newObject
    else:
        print "Uknown Type"
    
    return 0;

print 'getting config 1'
config1 = connectSSH(device1)

print 'getting config 2'
# config2 = connectSSH(device1)

print parseConfig(config1)



