local stdnse = require "stdnse"
local upnp = require "upnp"
local string = require "string"
local table = require "table"

description = [[
Enhanced version of broadcast-upnp-info that performs a security risk
assessment on discovered UPnP devices. In addition to extracting system
information via multicast query, this script analyzes each device for
potential security concerns including exposed service types, known
vulnerable UPnP implementations, and risky device configurations.
Each device is assigned a risk severity level (LOW, MEDIUM, HIGH,
CRITICAL) based on the analysis, and actionable security
recommendations are provided.

Enhancement over base script (broadcast-upnp-info.nse):
  * Identifies risky UPnP service types (WANIPConnection, RemoteAccess, etc.)
  * Detects known vulnerable UPnP stacks (old MiniUPnPd, Intel SDK, libupnp)
  * Flags Internet Gateway Devices and WAN-exposed services
  * Assigns a per-device risk severity rating
  * Produces actionable security recommendations
  * Counts total devices and reports overall network risk level
]]

---
-- @usage
-- nmap --script broadcast-upnp-info-security-risk
--
-- @output
-- | broadcast-upnp-info-security-risk:
-- |
-- |   ===== UPnP Device Discovery =====
-- |   IP: 172.20.166.5
-- |     Server: Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0
-- |     Location: http://172.20.166.5:2869/upnphost/...
-- |     Name: OmniBook
-- |     Manufacturer: Microsoft Corporation
-- |     Device Type: MediaRenderer
-- |
-- |   ===== Security Risk Assessment =====
-- |   Total Devices: 1
-- |   Overall Risk: MEDIUM
-- |
-- |   Device 172.20.166.5 [MEDIUM]:
-- |     [MEDIUM] Broadcom UPnP stack detected
-- |
-- |   Recommendations:
-- |     - Restrict UPnP access to trusted LAN segments only
-- |_    - Monitor UPnP traffic with IDS/IPS rules

-- Version 1.0 - Enhanced with security risk assessment
-- Based on broadcast-upnp-info v0.1 by Patrik Karlsson

author = "Enhanced by Student (based on Patrik Karlsson's broadcast-upnp-info)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


-----------------------------------------------------------------------
-- Risk databases
-----------------------------------------------------------------------

-- Known risky UPnP service types
local risky_services = {
  ["WANIPConnection"]          = { level = "HIGH",     desc = "Allows external port mapping - potential NAT traversal abuse" },
  ["WANPPPConnection"]         = { level = "HIGH",     desc = "PPP connection control exposed - potential credential leak" },
  ["WANCommonInterfaceConfig"] = { level = "MEDIUM",   desc = "WAN interface config exposed - information disclosure risk" },
  ["LANHostConfigManagement"]  = { level = "MEDIUM",   desc = "LAN host configuration exposed - potential DHCP manipulation" },
  ["RemoteAccess"]             = { level = "CRITICAL", desc = "Remote access service detected - high risk if unauthenticated" },
  ["DeviceProtection"]         = { level = "LOW",      desc = "Device protection service present (positive indicator)" },
  ["DeviceSecurity"]           = { level = "LOW",      desc = "Device security service present" },
}

-- Known risky device type keywords
local risky_device_types = {
  ["InternetGateway"]   = { level = "MEDIUM", desc = "UPnP Internet Gateway Device - potential port mapping abuse" },
  ["WANDevice"]         = { level = "MEDIUM", desc = "WAN device exposed via UPnP" },
  ["WANConnection"]     = { level = "HIGH",   desc = "WAN connection device directly controllable via UPnP" },
}

-- Known outdated / vulnerable UPnP stack signatures
local risky_servers = {
  { pattern = "MiniUPnPd/1%.[0-4]",   level = "HIGH",   desc = "Outdated MiniUPnPd (<1.5) - CVE-2013-0229, CVE-2013-0230" },
  { pattern = "Intel SDK for UPnP",    level = "HIGH",   desc = "Intel UPnP SDK - historically vulnerable to buffer overflows" },
  { pattern = "Portable SDK for UPnP", level = "HIGH",   desc = "libupnp detected - CVE-2012-5958 through CVE-2012-5965" },
  { pattern = "Realtek",               level = "MEDIUM", desc = "Realtek UPnP implementation - often weak defaults" },
  { pattern = "Broadcom",              level = "MEDIUM", desc = "Broadcom UPnP stack - common in ISP-provided routers" },
}

-- Risk level numeric priority
local risk_priority = {
  LOW      = 1,
  MEDIUM   = 2,
  HIGH     = 3,
  CRITICAL = 4,
}


-----------------------------------------------------------------------
-- Risk analysis helpers
-----------------------------------------------------------------------

--- Deep-scan all string values in a table for risk indicators
-- @param tbl    table to scan recursively
-- @param risks  table to append risk items into (mutated in-place)
-- @return max_risk string  highest risk level found
local function scan_table_for_risks(tbl, risks)
  local max_risk = "LOW"
  local seen_desc = {}  -- deduplicate

  local function check_and_add(level, desc)
    if seen_desc[desc] then return end
    seen_desc[desc] = true
    risks[#risks + 1] = { level = level, description = desc }
    if risk_priority[level] > risk_priority[max_risk] then
      max_risk = level
    end
  end

  local function scan(val)
    if type(val) == "string" then
      -- Check server-header signatures
      for _, entry in ipairs(risky_servers) do
        if string.find(val, entry.pattern) then
          check_and_add(entry.level, entry.desc)
        end
      end
      -- Check device-type keywords
      for keyword, info in pairs(risky_device_types) do
        if string.find(val, keyword) then
          check_and_add(info.level, info.desc)
        end
      end
      -- Check service-type keywords
      for keyword, info in pairs(risky_services) do
        if string.find(val, keyword) then
          check_and_add(info.level, "Exposes " .. keyword .. " service - " .. info.desc)
        end
      end
    elseif type(val) == "table" then
      for _, v in pairs(val) do
        scan(v)
      end
    end
  end

  scan(tbl)
  return max_risk
end


--- Generate actionable recommendations based on risk level
local function generate_recommendations(risks, max_risk)
  local recs = {}
  local seen = {}

  local function add(msg)
    if not seen[msg] then
      recs[#recs + 1] = msg
      seen[msg] = true
    end
  end

  if risk_priority[max_risk] >= risk_priority["HIGH"] then
    add("Disable UPnP on this device if not strictly required")
  end
  if risk_priority[max_risk] >= risk_priority["MEDIUM"] then
    add("Restrict UPnP access to trusted LAN segments only")
  end

  for _, r in ipairs(risks) do
    if string.find(r.description, "Outdated") or string.find(r.description, "CVE") then
      add("Update device firmware to the latest available version")
    end
    if string.find(r.description, "port mapping") then
      add("Audit active UPnP port mappings regularly")
    end
    if string.find(r.description, "Remote") then
      add("Verify remote access service requires strong authentication")
    end
  end

  add("Monitor UPnP traffic with IDS/IPS rules")
  return recs
end


--- Recursively collect all string values from a table (for display)
local function collect_device_fields(tbl, prefix, lines)
  prefix = prefix or ""
  for k, v in pairs(tbl) do
    if type(v) == "string" then
      lines[#lines + 1] = prefix .. tostring(k) .. ": " .. v
    elseif type(v) == "table" then
      lines[#lines + 1] = prefix .. tostring(k) .. ":"
      collect_device_fields(v, prefix .. "  ", lines)
    end
  end
end


-----------------------------------------------------------------------
-- NSE entry points
-----------------------------------------------------------------------

prerule = function() return true end

action = function()
  -- 1. Perform standard UPnP multicast discovery
  local helper = upnp.Helper:new()
  helper:setMulticast(true)
  local status, result = helper:queryServices()

  if not status then
    return stdnse.format_output(false, "UPnP discovery returned no results.")
  end

  -- 2. Build the output by iterating through the result table
  local out = {}
  local device_count = 0
  local overall_max_risk = "LOW"
  local all_device_risks = {}  -- { {ip=..., risks=..., max_risk=...}, ... }

  out[#out + 1] = ""
  out[#out + 1] = "===== UPnP Device Discovery ====="

  -- The result from queryServices with multicast is a sorted output_table
  -- where each key is an IP and value is a device info table
  for ip, device_info in pairs(result) do
    device_count = device_count + 1
    out[#out + 1] = ""
    out[#out + 1] = "  IP: " .. tostring(ip)

    -- Display device info fields
    if type(device_info) == "table" then
      local lines = {}
      collect_device_fields(device_info, "    ", lines)
      for _, line in ipairs(lines) do
        out[#out + 1] = line
      end

      -- Run risk analysis on this device
      local dev_risks = {}
      local dev_max = scan_table_for_risks(device_info, dev_risks)
      if risk_priority[dev_max] > risk_priority[overall_max_risk] then
        overall_max_risk = dev_max
      end
      all_device_risks[#all_device_risks + 1] = {
        ip = tostring(ip),
        risks = dev_risks,
        max_risk = dev_max,
      }
    elseif type(device_info) == "string" then
      out[#out + 1] = "    " .. device_info
    end
  end

  -- 3. Security Risk Assessment section
  out[#out + 1] = ""
  out[#out + 1] = "===== Security Risk Assessment ====="
  out[#out + 1] = "  Total Devices: " .. device_count
  out[#out + 1] = "  Overall Network Risk: " .. overall_max_risk

  for _, dev in ipairs(all_device_risks) do
    out[#out + 1] = ""
    out[#out + 1] = "  Device " .. dev.ip .. " [" .. dev.max_risk .. "]:"
    if #dev.risks == 0 then
      out[#out + 1] = "    [LOW] No high-risk services or vulnerabilities detected"
    else
      for _, r in ipairs(dev.risks) do
        out[#out + 1] = "    [" .. r.level .. "] " .. r.description
      end
    end
  end

  -- 4. Recommendations
  local all_risks = {}
  for _, dev in ipairs(all_device_risks) do
    for _, r in ipairs(dev.risks) do
      all_risks[#all_risks + 1] = r
    end
  end
  local recs = generate_recommendations(all_risks, overall_max_risk)
  out[#out + 1] = ""
  out[#out + 1] = "  Recommendations:"
  for _, rec in ipairs(recs) do
    out[#out + 1] = "    - " .. rec
  end

  return table.concat(out, "\n")
end
