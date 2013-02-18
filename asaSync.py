#!/usr/bin/env python

import difflib
import pexpect
import re

user     = ""
password = ""
device1  = ""
device2  = ""

class Acl:
    aclName    = ""
    aclType    = ""
    action     = ""
    extended   = ""
    lineNumber = 0
    remark     = ""
    
    def __eq__(self, other):
        try:
            if self.aclName != other.aclName:
                return False
            
            if self.action != other.action:
                return False
            
            if self.remark != other.remark:
                return False
            
            if self.extended != other.extended:
                return False
            
            if self.aclType != other.aclType:
                return False
        
        except (AttributeError, TypeError, ValueError):
            return False
        
        # Default Condition        
        return True
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __str__(self):
        result = "access-list " + self.aclName + " "
        
        if self.aclType == "ethertype":
            result += "ethertype " + self.action + " " + self.extended
        elif self.aclType == "extended":
            result += "extended " + self.action + " " + self.extended
            
            #Temp to show remark
            if self.remark != "":
                result += " Remark: " + self.remark
        elif self.aclType == "remark":
            result += "remark " + self.remark
        else:
            result = "~Error: action: " + self.action + " remark: " + self.remark + " extended: " + self.extended + " aclType: " + self.aclType
        
        return result

class Config:
    acls         = []
    netObjects   = []
    objectGroups = []    
    
    # Checks to see if this config contains a NetworkObject with the same name as the passed object
    # If yes, then the matching object is returned, if no; False is returned. 
    def containsNetObject(self, networkObject): 
        for netObject in self.netObjects:
            if netObject.name == networkObject.name:
                return netObject
        
        return False
    
    # Checks to see if this config contains a ObjectGroup with the same name as the passed object
    # If yes, then the matching object is returned, if no, False is returned
    def containsObjectGroup(self, objectGroup): 
        for objGroup in self.objectGroups:
            if objGroup.name == objectGroup.name:
                return objGroup 
        
        return False    
    
    # Checks to see if this config contains an Acl with the same name and line number as the
    # passed object.  If yes, then the matching acl is returned, if no, False is returned
    def containsAcl(self, acl): 
        for accessList in self.acls:
            if accessList.aclName == acl.aclName and accessList.lineNumber == acl.lineNumber:
                return accessList
        
        return False    
    
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
    
    def __eq__(self, other):
        if self.ip == other.ip:
            return True
        else:
            return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __str__(self):
        return " host " + self.ip;

class Subnet:
    ip   = "0.0.0.0"
    mask = "255.255.255.255"
    
    def __eq__(self, other):
        if self.ip == other.ip and self.mask == other.mask:
            return True
        else:
            return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __str__(self):
        return " subnet " + self.ip + " " + self.mask;    

class Range:
    ipStart = "0.0.0.0"
    ipEnd   = "0.0.0.0"
    
    def __eq__(self, other):
        if self.ipStart == other.ipStart and self.ipEnd == other.ipEnd:
            return True
        else:
            return False
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __str__(self):
        return " range " + self.ipStart + " " + self.ipEnd;    

class NetworkObject:
    name    = ""
    hosts   = []
    subnets = []
    ranges  = []
    
    def __eq__(self, other):
        try:
            #Check Name
            if self.name != other.name:
                return False
            
            #Check Hosts
            for index in range(len(self.hosts)):
                if self.hosts[index] != other.hosts[index]:
                    return False
            
            #Check Subnets
            for index in range(len(self.subnets)):
                if self.subnets[index] != other.subnets[index]:
                    return False
            
            #Check Ranges
            for index in range(len(self.ranges)):
                if self.ranges[index] != other.ranges[index]:
                    return False
        
        except (AttributeError, TypeError, ValueError):
            return False
        
        #Default condition
        return True
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __str__(self):
        count = len(self.hosts) + len(self.subnets) + len(self.ranges)
        
        if count > 1:
            result = "object-group network " + self.name + "\n"
        else:
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
    
    def __eq__(self, other):
        try:
            #Check Name
            if self.name != other.name:
                return False
            
            #Check Group Type
            if self.groupType != other.groupType:
                return False
            
            #Check Service Type
            if self.serviceType != other.serviceType:
                return False
            
            #Check Type Lists
            for index in range(len(self.typeList)):
                if self.typeList[index] != other.rtypeList[index]:
                    return False            
            
            #Check Value Lists
            for index in range(len(self.valueList)):
                if self.valueList[index] != other.valueList[index]:
                    return False 
        
        except (AttributeError, TypeError, ValueError):
            return False
        
        #Default condition
        return True
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
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

def compareConfigs(config1, config2):
    aclsToSync         = []
    netObjectsToSync   = []
    objectGroupsToSync = []
    
    #Check sync between Network Objects
    for netObject in config1.netObjects:
        netObject2 = config2.containsNetObject(netObject)
        
        if netObject != False:
            #Both configs have this NetObject, compare them
            if netObject != netObject2:
                netObjectsToSync.append(netObject)
        else:
            #The second config does not conaint this object
            netObjectsToSync.append(netObject)
    
    #Check sync between ObjectGroups
    for objectGroup in config1.objectGroups:
        objectGroup2 = config2.containsObjectGroup(objectGroup)
        
        if netObject != False:
            #Both configs have this Object Group, compare them
            if objectGroup != objectGroup2:
                objectGroupsToSync.append(objectGroup)
        else:
            #The second config does not conaint this object
            objectGroupsToSync.append(objectGroup)        
    
    
    #Check sync between Alcs
    for acl in config1.acls:
        acl2 = config2.containsAcl(acl)
        
        if netObject != False:
            #Both configs have this acl, compare them
            if acl != acl2:
                aclsToSync.append(acl)
        
        else:
            #The second config does not conaint this acl
            aclsToSync.append(acl)


#Temp - Show Differences
#print "~Diffs"

#for netObject in netObjectsToSync:
#print netObject

#for objectGroup in objectGroupsToSync:
#print objectGroup

#for acl in aclsToSync:
#print acl

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
    acls       = []
    eList      = config.split()
    index      = 0
    lineNumber = 0
    remark     = False
    
    while index < len(eList):
        try:
            if remark == False:
                newAcl = Acl()
                newAcl.remark = ""
                newAcl.action = ""
            
            index   = eList.index("access-list", index)
            index  += 1
            
            # ACL Remark Match Check
            if remark == True and newAcl.aclName != eList[index]:
                print "~Error: Remark for ACL with different name."
            
            newAcl.aclName = eList[index]
            index  += 1
            newAcl.aclType = eList[index]
            
            if newAcl.aclType == "ethertype":
                index  += 1
                newAcl.action   = eList[index]
                index  += 1
                
                try:
                    endIndex    = eList.index("access-list", index)
                except ValueError:
                    endIndex    = len(eList)
                
                newAcl.extended = " ".join(eList[index:endIndex])
                
                # Reset remark flag, so acls are not added to previous an ACL
                remark = False               
            elif newAcl.aclType == "extended":
                index  += 1
                
                try:
                    endIndex    = eList.index("access-list", index)
                except ValueError:
                    endIndex    = len(eList)
                
                newAcl.action   = eList[index]
                newAcl.extended = " ".join(eList[index:endIndex])
                
                # Reset remark flag, so acls are not added to previous an ACL
                remark = False                
            elif newAcl.aclType == "remark":
                # Remarks are comments for the next line of ACL
                
                try:
                    endIndex    = eList.index("access-list", index)
                except ValueError:
                    endIndex    = len(eList)
                
                index          += 1
                newAcl.remark   = " ".join(eList[index:endIndex])
                newAcl.extended = ""
                
                #Set the remark flag to True so that the next acl gets added to the remark
                remark = True
            else:
                print "~Unknown ACL Type"
            
            newAcl.lineNumber = lineNumber
            
            if remark == False:
                acls.append(newAcl)
            
            lineNumber += 1
        except ValueError:
            # End of ACL List
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

# get config 1
config1Text = connectSSH(device1)

# get config 2
config2Text = connectSSH(device2)

config1 = parseConfig(config1Text)
config2 = parseConfig(config2Text)

compareConfigs(config1, config2)


