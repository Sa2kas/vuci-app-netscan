#! /usr/bin/env lua

local cjson = require "cjson"
local argparse = require "argparse"

local parser = argparse("nethosts", "Scan a network for hosts")
parser:option("-a --ipsubnet", "Specific ipv4 subnet to scan")
local args = parser:parse()

Hosts = "/tmp/hosts.json"

NetworkDatabase = { }

NetworkDatabase.Subnets = {

    {   ipv4subnet = "192.168.10.0/24",
        description = "My home LAN",
    },
}

if args.ipsubnet ~= nil then
    NetworkDatabase.Subnets[1].ipv4subnet = args.ipsubnet
end

NetworkDatabase.KnownHosts = {

    {   macAddr = "AA:BB:01:02:CC:DD",
        description = "My laptop's Wifi",
        vendor = "Big Computer Maker, Inc.",
    },

    {   macAddr = "44:55:EE:FF:66:77",
        description = "My home Wifi router",
    },
}

local DatabaseOfHostsByMAC = { }

local AllDiscoveredHosts = { }

local minCIDR = 16

--------------------------------------------------------------------------------

function validateIPv6subnet ( subnet, description )

    if not subnet then return end

    print( "IPv6 subnet support is not (yet) implemented!" )
    print( "Cannot scan subnet '"..description.."'; skipping..." )
end

function validateIPv4subnet ( subnet, description )
    local Octets = { }
    local cidr

    if type(subnet) ~= "string" then return end

    description = description or "<no-name>"

    Octets = {
        subnet:match( "(%d+)%.(%d+)%.(%d+)%.(%d+)%/(%d+)" ),
        }

    cidr,Octets[5] = Octets[5],cidr

    if not cidr then
        error( "Bad subnet: CIDR value missing for subnet '"..description.."'" )
    end

    cidr = tonumber( cidr )

    if cidr < minCIDR or cidr > 32 then
        error( "Bad subnet: CIDR value ("..cidr..
            ") out of range ("..minCIDR..
            "..32) for subnet '"..description.."'" )
    end

    for index, octet in ipairs( Octets ) do

        octet = tonumber( octet )

        if octet < 0 or octet > 255 then
            error( "Subnet octet #"..index.." for '"..
                description.."' is out of range (0..255)" )
        end
    end
end

-------------------------------------------------------------------------------

function validateSubnets ( Subnets )
    local dataType = type( Subnets )

    if dataType ~= "table" then
        error "Missing or corrupt 'Subnets' table in Network Database file!"
    end

    for index, Subnet in ipairs( Subnets ) do

        if dataType ~= "table" then
            error( "Found a '"..dataType.."' for 'Subnets' element "..
                index.." in the Network Database file!" )
        end

        validateIPv4subnet( Subnet.ipv4subnet, Subnet.description )
        validateIPv6subnet( Subnet.ipv6subnet, Subnet.description )
    end
end

-------------------------------------------------------------------------------

function validateMACaddress ( macAddress, index )
    local dataType = type( KnownHosts )
    index = index or "<unknown>"

    if type(macAddress) ~= "string" then
        error( "Host #"..index..
            " in the Network Database file has no MAC address!" )
    end

    Octets = {
        macAddress:match( "(%x%x)%:(%x%x)%:(%x%x)%:(%x%x)%:(%x%x)%:(%x%x)" ),
        }

    for index, octet in ipairs( Octets ) do

        octet = tonumber( octet, 16 )

        if octet < 0 or octet > 255 then
            error( "Subnet octet #"..index.." for '"..
                description.."' is out of range (0..255)" )
        end
    end

    return macAddress:upper()
end

-------------------------------------------------------------------------------

function validateKnownHosts ( KnownHosts )
    local dataType = type( KnownHosts )

    if dataType ~= "table" then
        error "Missing or corrupt 'KnownHosts' table in Network Database file!"
    end

    for index, KnownHost in ipairs( KnownHosts ) do

        if dataType ~= "table" then
            error( "Found a '"..dataType.."' for 'KnownHosts' element "..
                index.." in the Network Database file!" )
        end

        local macAddress = KnownHost.macAddr

        if type(macAddress) ~= "string" then
            error( "Host #"..index..
                " in the Network Database file has no MAC address!" )
        end

        KnownHost.macAddr = validateMACaddress( macAddress, index )

        if type( KnownHost.description ) ~= "string" then
            error( "Host #"..index..
                " in the Network Database file has no description!" )
        end
    end
end

-------------------------------------------------------------------------------

function validateNetworkDatabase ( Database )

    validateSubnets( Database.Subnets )

    validateKnownHosts( Database.KnownHosts )
end

-------------------------------------------------------------------------------

function sortHostsByMACaddress ( DatabaseOfHosts )
    HostsByMAC = { }

    for index, DatabaseHost in ipairs( DatabaseOfHosts ) do

        HostsByMAC[ DatabaseHost.macAddr ] = DatabaseHost
    end

    return HostsByMAC
end

-------------------------------------------------------------------------------

function runShellCommand( shellCommand, resultHandler )
    local tempFile = "/tmp/lua-shell-cmd"

    if not os.execute( shellCommand.." > "..tempFile ) then
        error( "Execution of OS command '"..shellCommand.."' failed!" )
    end

    if not io.input( tempFile ) then
        error( "Cannot open file '"..tempFile..
            "' containing OS command results!" )
    end

    for line in io.lines() do
        if line:match( "%w" ) then
            resultHandler = resultHandler( line )

            if not resultHandler then break end
        end
    end

    io.input():close()
    os.remove( tempFile )
end

-------------------------------------------------------------------------------

function ScanNetworkForHosts ( Subnet )
    local AllDiscoveredHosts = { }

    local thisSubnet = Subnet.ipv4subnet

    if not thisSubnet then
        thisSubnet = "-6 "..Subnet.ipv6subnet
    end

    local shellCommand = "nmap -n -sP "..thisSubnet

    local resultHandlerInitial
    local resultHandlerMiddle
    local resultHandlerFinal


    resultHandlerInitial = function ( line )
        local ipNumber = line:match( "Nmap scan report for (%S+)" )

        if ipNumber then
            AllDiscoveredHosts[ #AllDiscoveredHosts + 1 ] =
                { ipNumber=ipNumber }

            return resultHandlerMiddle
        end

        if not line:match( "Starting Nmap" ) then
            error( "Could not detect start of 'nmap' scan!" )
        end

        return resultHandlerInitial
    end


    resultHandlerMiddle = function ( line )
        local status = line:match( "Host is (%w+)" )

        if not status then
            error( "Network scan failed for host with IP '"..
                AllDiscoveredHosts[ #AllDiscoveredHosts ].ipNumber.."'! " )
        end

        AllDiscoveredHosts[ #AllDiscoveredHosts ].status = status

        return resultHandlerFinal
    end


    resultHandlerFinal = function ( line )
        local macAddr, vendor = line:match( "MAC Address: (%S+)%s+(.+)" )

        if macAddr then
            AllDiscoveredHosts[ #AllDiscoveredHosts ].macAddr = macAddr:upper()
            AllDiscoveredHosts[ #AllDiscoveredHosts ].vendor  = vendor

            return resultHandlerInitial
        end

        if AllDiscoveredHosts[1].ipNumber and
            not AllDiscoveredHosts[1].macAddr then
                error( "NMAP is not returning MAC addresses;"..
                    " is 'sudo' working?" )
        end

        if not line:match( "Nmap done" ) then
            error( "Could not detect end of 'nmap' scan!" )
        end

    end

    runShellCommand( shellCommand, resultHandlerInitial )
    return AllDiscoveredHosts
end

-------------------------------------------------------------------------------

function getAllMyNICs ( )
    local MyNICs = { }
    local shellCommand = "ip -br addr"
    local resultHandler

    resultHandler = function ( line )
        local deviceName, ipNumber = line:match( "(%w+)%s+UP%s+([^/]+)" )

        if deviceName then MyNICs[ #MyNICs + 1 ] =
            { deviceName=deviceName, ipNumber=ipNumber }
        end

        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return MyNICs
end

-------------------------------------------------------------------------------

function getAllMyMACs ( )
    local MyMACs = { }
    local shellCommand = "ip -o -f link addr"
    local resultHandler

    resultHandler = function ( line )
        local deviceName, macAddr = line:match( "%d+: (%w+):.+ether (%S+)" )

        if deviceName then MyMACs[ #MyMACs + 1 ] =
            { deviceName=deviceName, macAddr=macAddr:upper() }
        end

        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return MyMACs
end

-------------------------------------------------------------------------------

function getMyVendor ( myMACaddress )
    local myVendorName
    local shellCommand = "lshw"

    if myMACaddress and vendor then
        myVendorName = DatabaseOfHostsByMAC[ myMACaddress ].vendor

        if myVendorName then return myVendorName end
    end

    local resultHandler

    resultHandler = function ( line )
        myVendorName = line:match( "vendor: ([^]]+)" )

        if myVendorName then return end

        return resultHandler
    end

    runShellCommand( shellCommand, resultHandler )
    return myVendorName
end

-------------------------------------------------------------------------------

function myNICnameFromIPnumber ( myIPnumber )
    if not myIPnumber then
        error "Cannot resolve an interface name from a 'nil' IP number!"
    end

    for _, ThisNIC in ipairs( getAllMyNICs() ) do
        if not ThisNIC or not ThisNIC.ipNumber then
            error( "Network interface '"..ThisNIC.deviceName..
                "' has no IP number!" )
        end

        if ThisNIC.ipNumber == myIPnumber then
            if ThisNIC.deviceName then return ThisNIC.deviceName end

            error( "Network interface with IP number '"..
                ThisNIC.ipNumber.."' has no description!" )
        end
    end

    error( "Cannot find my own network interface device!" )
end

-------------------------------------------------------------------------------

function myMACaddrFromNICname ( myNICname )
    if not myNICname then
        error "Cannot resolve a MAC address from a 'nil' interface name!"
    end

    for _, ThisMAC in ipairs( getAllMyMACs() ) do

        if not ThisMAC or not ThisMAC.deviceName then
            error( "Network interface '"..ThisMAC.macAddr..
                "' has no device name!" )
        end

        if ThisMAC.deviceName == myNICname then
            if ThisMAC.macAddr then return ThisMAC.macAddr end

            error( "Network interface '"..
                ThisMAC.deviceName.."' has no MAC address!" )
        end
    end

    error( "Cannot find my own network device's MAC address!" )
end

-------------------------------------------------------------------------------

function getMyMacAddr ( myIPnumber )

    local myNICname = myNICnameFromIPnumber( myIPnumber )

    return myMACaddrFromNICname( myNICname )
end

-------------------------------------------------------------------------------

function findHostsOnNetwork ( Subnet )
    local MyHost
    local subnetDescr = Subnet.description

    DiscoveredHosts = ScanNetworkForHosts( Subnet )

    if #DiscoveredHosts < 1 then
        error( "Scan of network "..subnetDescr..
            " did not return ANY hosts! " )
    end

    MyHost = DiscoveredHosts[ #DiscoveredHosts ]

    MyHost.macAddr = getMyMacAddr( MyHost.ipNumber )
    -- MyHost.vendor = "("..getMyVendor( MyHost.macAddr )..")"

    DiscoveredHosts[ #DiscoveredHosts ] = MyHost

    return DiscoveredHosts
end

-------------------------------------------------------------------------------
function sortHostsByFamiliarity ( HostsFoundOnNetwork )
    local HostsThatAreKnown   = { }
    local HostsThatAreUnknown = { }

    for _, ThisNetworkHost in ipairs( HostsFoundOnNetwork ) do
        if not ThisNetworkHost.macAddr then
            error( "MAC address missing for discovered host at IP number '"..
                ThisNetworkHost.ipNumber.."' " )
        end

        local DatabaseHost = DatabaseOfHostsByMAC[ ThisNetworkHost.macAddr ]

        if DatabaseHost then
            ThisNetworkHost.description = DatabaseHost.description

            HostsThatAreKnown[ #HostsThatAreKnown + 1 ] = ThisNetworkHost
        else
            HostsThatAreUnknown[ #HostsThatAreUnknown + 1 ] = ThisNetworkHost
        end
    end

    return HostsThatAreKnown, HostsThatAreUnknown
end

-------------------------------------------------------------------------------

function printHostReportRecord ( familiarityTag, NetworkHost )
    local ipNumberString = NetworkHost.ipNumber
    local macAddrString  = NetworkHost.macAddr
    local description    = NetworkHost.description
    local reportFormat = "%s host: IP number %-14s MAC addr %s %s "
    local jsonFormat = "{\"host\":\"%s\",\"IP\":\"%s\",\"MAC\":\"%s\"}"

    if description then
        description = "  descr: "..description
    else
        description = ""
    end

    -- Use the provided format string to print this host record.
    -- print( string.format( reportFormat,
    --     familiarityTag, ipNumberString, macAddrString, description ) )
    -- io.write(string.format(jsonFormat, familiarityTag, ipNumberString, macAddrString))
end

-------------------------------------------------------------------------------

function printHostReport ( Subnet, SortedHosts, familiarityTag )

    if #SortedHosts == 0 then
        -- print( string.format( "No hosts found.") )
        return
    end

    for _, ThisHost in ipairs( SortedHosts ) do

        printHostReportRecord( familiarityTag, ThisHost )
    end
end

-------------------------------------------------------------------------------

function genNetworkHostsReport ( Subnet,
        HostsThatAreKnown, HostsThatAreUnknown )
    local isKnownTag   = "Known"
    local isUnknownTag = "Unknown"

    printHostReport( Subnet, HostsThatAreKnown, isKnownTag )

    printHostReport( Subnet, HostsThatAreUnknown, isUnknownTag )
end

-------------------------------------------------------------------------------

function printResultToFile ( status, NetworkHost )
    -- hosts = io.open(Hosts, "w")
    -- hosts:write(cjson.encode({hosts = NetworkHost, scan = status}))
    -- hosts:close()
    io.write(cjson.encode({hosts = NetworkHost, scan = status}))
end

-------------------------------------------------------------------------------

function main ( Database )
    local HostsThatAreKnown
    local HostsThatAreUnknown
    io.open(Hosts, "w"):close()
    	
    -- printResultToFile ( "started" )
    
    validateNetworkDatabase( Database )

    DatabaseOfHostsByMAC = sortHostsByMACaddress( Database.KnownHosts )

    for _, Subnet in ipairs( Database.Subnets ) do

        AllDiscoveredHosts = findHostsOnNetwork( Subnet )
        
        -- printResultToFile( "in progress", AllDiscoveredHosts )

        HostsThatAreKnown, HostsThatAreUnknown =
            sortHostsByFamiliarity( AllDiscoveredHosts )

        genNetworkHostsReport( Subnet, HostsThatAreKnown, HostsThatAreUnknown )
    end
    printResultToFile( "done", AllDiscoveredHosts )
end


main( NetworkDatabase )

-------------------------------------------------------------------------------