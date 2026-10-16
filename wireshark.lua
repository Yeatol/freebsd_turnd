local wireshark_proto_turn = Proto("TURN", "Traversal Using Relays around NAT")

local f_type           = ProtoField.uint16("turn.type",           "Message Type", base.HEX)
local f_length         = ProtoField.uint16("turn.length",         "Message Length", base.DEC)
local f_magic_cookie   = ProtoField.uint32("turn.magic_cookie",   "Message Cookie", base.HEX)
local f_transaction_id = ProtoField.bytes( "turn.transaction_id", "Message Transaction ID")
local f_turn_type      = ProtoField.uint16("turn.turn_type",      "Message Turn Type", base.HEX)
local f_x_peer_port    = ProtoField.bytes( "turn.x_peer_port",    "Message XOR Peer Port")
local f_x_peer_address = ProtoField.bytes( "turn.x_peer_address", "Message XOR Peer IP")
local f_payload        = ProtoField.bytes( "turn.payload",        "Message Payload")
local f_request        = ProtoField.framenum("turn.request",      "Request", base.NONE, frametype.REQUEST)
local f_response       = ProtoField.framenum("turn.response",     "Response", base.NONE, frametype.RESPONSE)

wireshark_proto_turn.fields = {
	f_type, f_length, f_magic_cookie, f_transaction_id,
	f_turn_type, f_x_peer_port, f_x_peer_address, f_payload,
	f_request, f_response
}

local e_payload_length = ProtoExpert.new("turn.payload_length_mismatch", "Payload length mismatch", expert.group.MALFORMED, expert.severity.WARN)
wireshark_proto_turn.experts = {e_payload_length}

local header_length = 40
local magic_cookie  = 0x12131017
local requests = {}
local responses = {}

function wireshark_proto_turn.init()
	requests = {}
	responses = {}
end

local function transaction_key(server_address, server_port, transaction_id, turn_type)
	return table.concat({
		tostring(server_address),
		tostring(server_port),
		transaction_id,
		string.format("%04x", turn_type)
	}, "|")
end

local function request_type(turn_type)
	if turn_type == 0x0001 or turn_type == 0x0002 then
		return turn_type
	end
	if turn_type == 0x0101 then
		return 0x0001
	end
	if turn_type == 0x0102 then
		return 0x0002
	end
	return nil
end

local function turn_info(turn_type, peer_address, peer_port)
	local info = ""
	if turn_type == 0x0001 then return string.format("Binding Request") end
	if turn_type == 0x0101 then return string.format("Binding Success Response XOR-MAPPED-ADDRESS: %s:%d", peer_address, peer_port) end
	if turn_type == 0x0002 then return string.format("Send XOR-PEER-ADDRESS: %s:%d", peer_address, peer_port) end
	if turn_type == 0x0102 then return string.format("Data XOR-PEER-ADDRESS: %s:%d", peer_address, peer_port) end
	return string.format("Unknown TURN Type 0x%04x", turn_type)
end

local function xor_byte(a, b)
	local result = 0
	local bit = 1
	for _ = 1, 8 do
		if a % 2 ~= b % 2 then
			result = result + bit
		end
		a = math.floor(a / 2)
		b = math.floor(b / 2)
		bit = bit * 2
	end
	return result
end

local function decode_peer_port(buffer)
	local high_byte = xor_byte(buffer(22, 1):uint(), buffer(4, 1):uint())
	local low_byte = xor_byte(buffer(23, 1):uint(), buffer(5, 1):uint())
	return high_byte * 256 + low_byte
end

local function decode_peer_address(buffer)
	local address_bytes = {}
	for i = 1, 16 do
		local key_offset = i <= 4 and (3 + i) or (i + 3)
		address_bytes[i] = xor_byte(buffer(23 + i, 1):uint(), buffer(key_offset, 1):uint())
	end

	local is_ipv4_mapped = address_bytes[11] == 0xff and address_bytes[12] == 0xff
	for i = 1, 10 do
		is_ipv4_mapped = is_ipv4_mapped and address_bytes[i] == 0
	end
	if is_ipv4_mapped then
		return string.format("::ffff:%d.%d.%d.%d",
			address_bytes[13], address_bytes[14], address_bytes[15], address_bytes[16])
	end

	local groups = {}
	for i = 1, 16, 2 do
		groups[#groups + 1] = string.format("%x", address_bytes[i] * 256 + address_bytes[i + 1])
	end

	local best_start, best_length
	local i = 1
	while i <= #groups do
		if groups[i] == "0" then
			local run_start = i
			while i <= #groups and groups[i] == "0" do
				i = i + 1
			end
			local run_length = i - run_start
			if run_length >= 2 and (best_length == nil or run_length > best_length) then
				best_start, best_length = run_start, run_length
			end
		else
			i = i + 1
		end
	end

	if best_start == nil then
		return table.concat(groups, ":")
	end

	local prefix = best_start == 1 and "::"
		or table.concat(groups, ":", 1, best_start - 1) .. "::"
	local suffix_start = best_start + best_length
	if suffix_start > #groups then
		return prefix
	end
	return prefix .. table.concat(groups, ":", suffix_start, #groups)
end

function wireshark_proto_turn.dissector(buffer, pinfo, tree)
	local packet_length = buffer:len()
	if packet_length < header_length or buffer(4, 4):uint() ~= magic_cookie then
		return 0
	end

	local payload_length = buffer(2, 2):uint()
	local captured_payload_length = packet_length - header_length
	local reported_payload_length = math.max(0, buffer:reported_len() - header_length)
	local peer_port = decode_peer_port(buffer)
	local peer_address = decode_peer_address(buffer)
	local turn_type = buffer(20, 2):uint()
	local transaction_id = buffer(8, 12):bytes():tohex()
	local paired_request_type = request_type(turn_type)
	local transaction

	if paired_request_type == 0x0001 or paired_request_type == 0x0002 then
		local server_address = (turn_type == 0x0001 or turn_type == 0x0002) and pinfo.dst or pinfo.src
		local server_port = (turn_type == 0x0001 or turn_type == 0x0002) and pinfo.dst_port or pinfo.src_port
		transaction = transaction_key(server_address, server_port, transaction_id, paired_request_type)
	end

	if transaction and not pinfo.visited then
		if turn_type == 0x0001 or turn_type == 0x0002 then
			if requests[transaction] == nil then
				requests[transaction] = pinfo.number
			end
		elseif responses[transaction] == nil and requests[transaction] ~= nil then
			responses[transaction] = pinfo.number
		end
	end

	pinfo.cols.protocol = "TURN"
	pinfo.cols.info = string.format("%s", turn_info(turn_type, peer_address, peer_port))

	local subtree = tree:add(wireshark_proto_turn, buffer())
	subtree:add(f_type, buffer(0, 2))
	subtree:add(f_length, buffer(2, 2))
	subtree:add(f_magic_cookie, buffer(4, 4))
	subtree:add(f_transaction_id, buffer(8, 12))
	subtree:add(f_turn_type, buffer(20, 2))
	subtree:add(f_x_peer_port, buffer(22, 2))
		:append_text(string.format(" (%d)", peer_port))
	subtree:add(f_x_peer_address, buffer(24, 16))
		:append_text(string.format(" (%s)", peer_address))

	if transaction then
		if turn_type == 0x0001 or turn_type == 0x0002 then
			local response_frame = responses[transaction]
			if response_frame ~= nil then
				subtree:add(f_response, response_frame):set_generated()
			end
		else
			local request_frame = requests[transaction]
			if request_frame ~= nil then
				subtree:add(f_request, request_frame):set_generated()
			end
		end
	end

	if captured_payload_length > 0 then
		subtree:add(f_payload, buffer(header_length, captured_payload_length))
	end
	if payload_length ~= reported_payload_length then
		pinfo.cols.info:append(string.format(
			" [Payload length mismatch: message_length=%d, payload_length=%d]", payload_length, reported_payload_length))
		subtree:add_proto_expert_info(e_payload_length, string.format(
			"Payload length mismatch: message_length=%d, payload_length=%d", payload_length, reported_payload_length))
	end

	return packet_length
end

wireshark_proto_turn:register_heuristic("udp", function(buffer, pinfo, tree)
    if buffer:len() < header_length or
        buffer(4, 4):uint() ~= magic_cookie then
        return false
    end
    wireshark_proto_turn.dissector(buffer, pinfo, tree)
    return true
end)