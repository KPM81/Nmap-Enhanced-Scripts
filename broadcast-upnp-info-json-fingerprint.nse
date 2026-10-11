local stdnse = require "stdnse"
local upnp = require "upnp"
local string = require "string"
local table = require "table"
local io = require "io"
local os = require "os"

description = [[
Enhanced version of broadcast-upnp-info that adds device fingerprinting
and JSON export capabilities. In addition to the standard UPnP multicast
discovery, this script:

  * Fingerprints the operating system and vendor from UPnP server headers
  * Classifies each device into a category (Router, Media Server, IoT,
    Smart TV, Printer, NAS, Camera, etc.)
  * Timestamps the discovery for audit trail purposes
  * Exports all results as a structured JSON file for integration with
    SIEM tools, asset inventories, or further automated analysis

Enhancement over base script (broadcast-upnp-info.nse):
  * OS / vendor fingerprinting from Server and User-Agent headers
  * Automatic device classification into meaningful categories
  * JSON export to a file (path configurable via script-arg)
  * Discovery timestamp for compliance and auditing
  * Device count summary
]]

---
-- @usage
-- nmap --script broadcast-upnp-info-json-fingerprint
-- nmap --script broadcast-upnp-info-json-fingerprint --script-args upnp_json_out=C:/Users/me/upnp_scan.json
--
-- @args upnp_json_out  Path where the JSON output file should be
--                      written.  Defaults to upnp_discovery.json in
--                      the current directory.
--
-- @output
-- | broadcast-upnp-info-json-fingerprint:
-- |
-- |   ===== UPnP Device Discovery =====
-- |   IP: 172.20.166.5
-- |     server: Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0
-- |     friendlyName: OmniBook
-- |     manufacturer: Microsoft Corporation
-- |     modelName: Windows Digital Media Renderer
-- |
-- |   ===== Device Fingerprinting =====
-- |   Device 1 [172.20.166.5]:
-- |     OS Fingerprint: Windows 10.0
-- |     Vendor: Microsoft Corporation
-- |     Category: Media Server
-- |     UPnP Stack: UPnP-Device-Host/1.0
-- |
-- |   ===== Export Summary =====
-- |   Devices found: 1
-- |   Scan timestamp: 2026-10-11 11:53:00
-- |_  JSON exported to: upnp_discovery.json

-- Version 1.0 - Enhanced with JSON export and device fingerprinting
-- Based on broadcast-upnp-info v0.1 by Patrik Karlsson

author = "Enhanced by Student (based on Patrik Karlsson's broadcast-upnp-info)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


-----------------------------------------------------------------------
-- OS fingerprint patterns  (Lua pattern → format string)
-----------------------------------------------------------------------
local os_patterns = {
  { pattern = "Microsoft%-Windows/(%S+)", label = "Windows %s" },
  { pattern = "Windows NT/(%S+)",         label = "Windows NT %s" },
  { pattern = "Windows/(%S+)",            label = "Windows %s" },
  { pattern = "Debian/(%S+)",             label = "Debian %s (Linux)" },
  { pattern = "Ubuntu/(%S+)",             label = "Ubuntu %s (Linux)" },
  { pattern = "Fedora/(%S+)",             label = "Fedora %s (Linux)" },
  { pattern = "Linux/(%S+)",              label = "Linux Kernel %s" },
  { pattern = "FreeBSD/(%S+)",            label = "FreeBSD %s" },
  { pattern = "Darwin/(%S+)",             label = "macOS (Darwin %s)" },
  { pattern = "Android/(%S+)",            label = "Android %s" },
  { pattern = "iOS/(%S+)",               label = "iOS %s" },
  { pattern = "POSIX",                    label = "POSIX-compliant OS" },
}

-----------------------------------------------------------------------
-- Device-category rules  (keywords → category)
-----------------------------------------------------------------------
local category_rules = {
  { keywords = { "InternetGateway", "WANDevice", "Router", "Gateway", "MiniUPnPd" },
    category = "Router/Gateway" },
  { keywords = { "DLNA", "MediaServer", "MiniDLNA", "Plex", "Serviio", "Twonky",
                  "Windows Media", "DLNADOC", "MediaRenderer", "Digital Media" },
    category = "Media Server" },
  { keywords = { "BRAVIA", "Samsung TV", "LG TV", "Roku", "Chromecast",
                  "Fire TV", "Smart TV", "KDL%-", "KD%-" },
    category = "Smart TV" },
  { keywords = { "Printer", "LaserJet", "Officejet", "EPSON", "Canon" },
    category = "Printer" },
  { keywords = { "Synology", "QNAP", "ReadyNAS", "NAS", "FreeNAS", "TrueNAS" },
    category = "NAS" },
  { keywords = { "Camera", "IPCam", "Webcam", "ONVIF", "Hikvision", "Dahua" },
    category = "Camera/Surveillance" },
  { keywords = { "IoT", "SmartHome", "Hue", "Sonos", "Echo", "HomePod", "Nest" },
    category = "IoT Device" },
}


-----------------------------------------------------------------------
-- Helpers
-----------------------------------------------------------------------

--- Escape a string for safe JSON inclusion
local function json_escape(s)
  if type(s) ~= "string" then return tostring(s) end
  s = s:gsub('\\', '\\\\')
  s = s:gsub('"',  '\\"')
  s = s:gsub('\n', '\\n')
  s = s:gsub('\r', '\\r')
  s = s:gsub('\t', '\\t')
  return s
end

--- Extract an OS fingerprint from a server-header string
local function fingerprint_os(server)
  if not server then return "Unknown" end
  for _, entry in ipairs(os_patterns) do
    local ver = string.match(server, entry.pattern)
    if ver then
      if string.find(entry.label, "%%s") then
        return string.format(entry.label, ver)
      else
        return entry.label
      end
    end
  end
  return "Unknown"
end

--- Extract the UPnP stack name from a server header
local function extract_upnp_stack(server)
  if not server then return "Unknown" end
  local stack = string.match(server, "UPnP/%S+%s+(.+)")
  return stack or "Unknown"
end

--- Classify a device into a category based on a blob of all its fields
local function classify_device(blob)
  if not blob then return "Generic UPnP Device" end
  for _, rule in ipairs(category_rules) do
    for _, kw in ipairs(rule.keywords) do
      if string.find(blob, kw) then
        return rule.category
      end
    end
  end
  return "Generic UPnP Device"
end

--- Collect all string values from a table into one big blob (for keyword matching)
local function table_to_blob(tbl)
  local parts = {}
  local function walk(t)
    for _, v in pairs(t) do
      if type(v) == "string" then
        parts[#parts + 1] = v
      elseif type(v) == "table" then
        walk(v)
      end
    end
  end
  walk(tbl)
  return table.concat(parts, " ")
end

--- Recursively display all fields of a table
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

--- Build a JSON string from a list of fingerprinted device records
local function build_json(devices, timestamp)
  local parts = {}
  parts[#parts + 1] = '{'
  parts[#parts + 1] = '  "scan_timestamp": "' .. json_escape(timestamp) .. '",'
  parts[#parts + 1] = '  "device_count": ' .. #devices .. ','
  parts[#parts + 1] = '  "devices": ['

  for i, dev in ipairs(devices) do
    parts[#parts + 1] = '    {'
    parts[#parts + 1] = '      "ip": "'            .. json_escape(dev.ip)            .. '",'
    parts[#parts + 1] = '      "os_fingerprint": "' .. json_escape(dev.os_fp)        .. '",'
    parts[#parts + 1] = '      "vendor": "'         .. json_escape(dev.vendor)        .. '",'
    parts[#parts + 1] = '      "category": "'       .. json_escape(dev.category)      .. '",'
    parts[#parts + 1] = '      "upnp_stack": "'     .. json_escape(dev.upnp_stack)    .. '",'
    parts[#parts + 1] = '      "server_header": "'  .. json_escape(dev.server)        .. '",'
    parts[#parts + 1] = '      "location": "'       .. json_escape(dev.location)      .. '",'
    parts[#parts + 1] = '      "friendly_name": "'  .. json_escape(dev.name)          .. '",'
    parts[#parts + 1] = '      "model_name": "'     .. json_escape(dev.model)         .. '",'
    parts[#parts + 1] = '      "manufacturer": "'   .. json_escape(dev.manufacturer)  .. '"'
    parts[#parts + 1] = i < #devices and '    },' or '    }'
  end

  parts[#parts + 1] = '  ]'
  parts[#parts + 1] = '}'
  return table.concat(parts, "\n")
end


-----------------------------------------------------------------------
-- NSE entry points
-----------------------------------------------------------------------

prerule = function() return true end

action = function()
  -- 1. Run standard UPnP multicast discovery
  local helper = upnp.Helper:new()
  helper:setMulticast(true)
  local status, result = helper:queryServices()

  if not status then
    return stdnse.format_output(false, "UPnP discovery returned no results.")
  end

  -- 2. Iterate the result table to display and fingerprint each device
  local out = {}
  local devices = {}   -- fingerprinted device records
  local device_count = 0

  out[#out + 1] = ""
  out[#out + 1] = "===== UPnP Device Discovery ====="

  for ip, device_info in pairs(result) do
    device_count = device_count + 1
    out[#out + 1] = ""
    out[#out + 1] = "  IP: " .. tostring(ip)

    -- Display raw device fields
    if type(device_info) == "table" then
      local lines = {}
      collect_device_fields(device_info, "    ", lines)
      for _, line in ipairs(lines) do
        out[#out + 1] = line
      end

      -- Fingerprint this device
      local blob   = table_to_blob(device_info)
      local server = device_info.server or device_info.webserver or ""

      local dev = {
        ip           = tostring(ip),
        server       = server,
        location     = device_info.location or "",
        name         = device_info.friendlyName or "",
        manufacturer = device_info.manufacturer or "",
        model        = device_info.modelName or "",
        vendor       = device_info.manufacturer or "Unknown",
        os_fp        = fingerprint_os(server),
        upnp_stack   = extract_upnp_stack(server),
        category     = classify_device(blob),
      }
      devices[#devices + 1] = dev
    end
  end

  -- 3. Fingerprinting section
  out[#out + 1] = ""
  out[#out + 1] = "===== Device Fingerprinting ====="
  for i, dev in ipairs(devices) do
    out[#out + 1] = string.format("  Device %d [%s]:", i, dev.ip)
    out[#out + 1] = "    OS Fingerprint: " .. dev.os_fp
    out[#out + 1] = "    Vendor: "         .. dev.vendor
    out[#out + 1] = "    Category: "       .. dev.category
    out[#out + 1] = "    UPnP Stack: "     .. dev.upnp_stack
    if i < #devices then out[#out + 1] = "" end
  end

  -- 4. Timestamp & JSON export
  local timestamp = os.date("%Y-%m-%d %H:%M:%S")
  local json_path = stdnse.get_script_args("upnp_json_out") or "upnp_discovery.json"
  local json_str  = build_json(devices, timestamp)
  local fh, err   = io.open(json_path, "w")
  local export_msg
  if fh then
    fh:write(json_str)
    fh:close()
    export_msg = "JSON exported to: " .. json_path
  else
    export_msg = "JSON export failed: " .. (err or "unknown error")
  end

  out[#out + 1] = ""
  out[#out + 1] = "===== Export Summary ====="
  out[#out + 1] = "  Devices found: "  .. device_count
  out[#out + 1] = "  Scan timestamp: " .. timestamp
  out[#out + 1] = "  " .. export_msg

  return table.concat(out, "\n")
end
