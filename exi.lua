-- File : exi.lua
-- Who  : Amit Geynis
-- What : EXI dissector

-- bitwise ops helpers
local band = bit.band

-- Efficient XML Interchange (EXI) Format 1.0

p_exi = Proto("exi","Efficient XML Interchange Format Header")

local f_cookie           = ProtoField.string("exi.cookie","EXI Cookie",base.ASCII)
local f_dbits            = ProtoField.uint8("exi.dbits","Distinguishing Bits",base.HEX,nil,0xC0)
local f_options_presence = ProtoField.bool("exi.options_presence","Presence Bit for EXI Options")
local f_version          = ProtoField.uint8("exi.version","EXI Format Version",base.HEX,nil,0x1F)


p_exi.fields = {f_cookie,f_dbits,f_options_presence,f_version}

-- Dissection function
function p_exi.dissector(buf,pinfo,root)
    pinfo.cols.protocol = "EXI Format"

	-- create subtree
	subtree = root:add(p_exi,buf(0))

	-- add protocol fields to subtree
	local offset = 0

	-- EXI Cookie
	if buf:len() >= 4 and buf(offset,4):string() == "$EXI" then
		subtree:add(f_cookie,buf(offset,4))
		offset = offset + 4
    end

    -- Distinguishing Bits
    subtree:add(f_dbits,buf(offset,1))

	-- Presence Bit for EXI Options
    subtree:add(f_options_presence,buf(offset,1):bitfield(2,1))

	-- EXI Format Version
	local version = band(buf(offset,1):uint(),0x1F)
	if band(version,0x1F) ~= 0x0F then
		local version_tree = subtree:add(f_version,buf(offset,1))
		if band(version,0x10) == 0 then
			version_tree:append_text(" Final Version " .. (band(version,0x0F) + 1))
		else
			version_tree:append_text(" Preview Version " .. (band(version,0x0F) + 1))
		end
	end

	offset = offset + 1

	-- TODO EXI Options, Padding, ...
	if buf:len() > offset then
		Dissector.get("data"):call(buf(offset):tvb(),pinfo,root)
	end
end