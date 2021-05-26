-- File : v2gtp.lua
-- Who  : Amit Geynis
-- What : V2G TP dissector

-- V2G TP protocol
local V2GTP_HDR_LENGTH = 8

p_v2gtp = Proto("v2gtp","Vehicle-to-Grid Transfer Protocol")

local f_pv  = ProtoField.uint8("v2gtp.protoversion","Protocol Version",base.HEX)
local f_ipv = ProtoField.uint8("v2gtp.inverseprotoversion","Inverse Protocol Version",base.HEX)
local f_pt  = ProtoField.uint16("v2gtp.payloadtype","Payload Type",base.HEX)
local f_len = ProtoField.uint32("v2gtp.length","Payload Length",base.HEX)

local EXI       = 32769
local SDP_REQ = 36864
local SDP_RES = 36865

local payload_types = {
    [EXI]     = "EXI encoded V2G Message",  -- 0x8001
    [SDP_REQ] = "SDP request message",      -- 0x9000
    [SDP_RES] = "SDP response message",     -- 0x9001
}


p_v2gtp.fields = {f_pv,f_ipv,f_pt,f_len}

p_v2gtp.prefs["udp_port"] = Pref.uint("UDP Port",15118,"UDP Port for V2G")


local function get_v2gtp_length(buf, pktinfo, offset)
    return buf(offset + 4,4):uint() + 8
end

-- PDU dissection function
local function v2gtp_pdu_dissect(buf,pinfo,root)
    local p_type_num = buf(2,2):uint()
    local prev_proto = tostring(pinfo.cols.protocol)

    pinfo.cols.protocol = "V2G TP"

    -- Delete irrelevant info from previous protocol
    if prev_proto ~= tostring(pinfo.cols.protocol) then
        pinfo.cols.info = ""
    end

    -- create subtree
    --
    subtree = root:add(p_v2gtp,buf(0))

    -- add protocol fields to subtree

    -- Protocol Version
    subtree:add(f_pv,buf(0,1))
    -- Inverse Protocol Version
    subtree:add(f_ipv,buf(1,1))

    -- Payload type
    local p_type = subtree:add(f_pt,buf(2,2))
    if payload_types[p_type_num] ~= nil then
        p_type:append_text(" (" .. payload_types[p_type_num] ..")")
        -- Concatenate the info of v2g
        if tostring(pinfo.cols.info) ~= "" then
            pinfo.cols.info = tostring(pinfo.cols.info) .. ", " .. payload_types[p_type_num]
        else
            pinfo.cols.info = payload_types[p_type_num]
        end
    end

    -- Length
    subtree:add(f_len,buf(4,4))

    -- EXI / SDP payload --
    --
    if (p_type_num == SDP_REQ) and (buf:len() > V2GTP_HDR_LENGTH)  then
        Dissector.get("v2gsdp-req"):call(buf(V2GTP_HDR_LENGTH):tvb(),pinfo,root)
    elseif (p_type_num == SDP_RES) and (buf:len() > V2GTP_HDR_LENGTH)  then
        Dissector.get("v2gsdp-res"):call(buf(V2GTP_HDR_LENGTH):tvb(),pinfo,root)
    elseif (p_type_num == EXI) and (buf:len() > V2GTP_HDR_LENGTH)  then
        Dissector.get("exi"):call(buf(V2GTP_HDR_LENGTH):tvb(),pinfo,root)
    end

    -- Dissect next V2GTP packet ?!?!--
    local end_of_current_packet = get_v2gtp_length(buf,pinfo,0)
    local next_packet_length = buf:len() - end_of_current_packet
    if next_packet_length > 0 then
        Dissector.get("v2gtp"):call(buf(end_of_current_packet):tvb(),pinfo,root)
    end
end

-- main dissection function
function p_v2gtp.dissector(buf,pinfo,root)
    -- if above TCP we need to assemble the PDU
    if pinfo.port_type == 2 then
        dissect_tcp_pdus(buf,root, V2GTP_HDR_LENGTH, get_v2gtp_length, v2gtp_pdu_dissect)
    else
        v2gtp_pdu_dissect(buf,pinfo,root)
    end
end

-- initialization routine
function p_v2gtp.init()
    -- register protocol
    DissectorTable.get("udp.port"):add(15118,p_v2gtp)
    DissectorTable.get("tcp.port"):add(15118,p_v2gtp)
    DissectorTable.get("tls.port"):add(15118,p_v2gtp)
end
