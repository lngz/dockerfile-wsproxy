local server = require "resty.websocket.server"
local vstruct = require "vstruct"

local with_conn_data = os.getenv("WSPROXY_CONN_DATA")

local origin_whitelist = {
}

local function check_origin()
    local origin = ngx.req.get_headers().origin

    if type(origin) ~= "string" then
        ngx.log(ngx.ERR, "only single origin expected, got: ", origin)
        return ngx.exit(400)
    end
    if not origin_whitelist[origin] then
        ngx.log(ngx.ERR, "origin not whitelisted: ", origin)
        return ngx.exit(403)
    end
end

local function ip_to_int(ip)
    local result = 0
    local mult = 16777216  -- 256^3
    for octet in string.gmatch(ip, "([^.]+)") do
        result = result + (tonumber(octet) * mult)
        mult = mult / 256
    end
    return result
end

local function build_conn_data()
    local fmt = vstruct.compile("< I4")
    local remote_addr = ngx.var.http_x_real_ip or ngx.var.remote_addr

    return fmt:write({
        ip_to_int(remote_addr)
    })
end

local function connect_mbbsd()
    local mbbsd = ngx.socket.stream()
    mbbsd:settimeout(5000)
    local ok, err = mbbsd:connect("127.0.0.1", 23)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect to mbbsd: ", err)
        return ngx.exit(555)
    end
    ngx.log(ngx.INFO, "connected to mbbsd ok")

    if with_conn_data == "1" then
        local conn_data = build_conn_data()
        ngx.log(ngx.INFO, "sending conn data: ", #conn_data, " bytes")
        local _, err = mbbsd:send(conn_data)
        if err then
           ngx.log(ngx.ERR, "failed to send conn data to mbbsd: ", err)
           return ngx.exit(555)
        end
    end

    return mbbsd
end

local function start_websocket_server()
    local ws, err = server:new({
        timeout = 30*60*1000,  -- in milliseconds
        max_payload_len = 65535,
    })
    if not ws then
        ngx.log(ngx.ERR, "failed to new websocket: ", err)
        return ngx.exit(444)
    end
    return ws
end

local function ws2sock(ws, sock)
    local last_typ = ""
    while true do
        local data, typ, err = ws:recv_frame()
        if err or not data then
            ngx.log(ngx.ERR, "failed to receive a frame: ", err)
            sock:close()
            return ngx.exit(444)
        end

        if typ == "continuation" then
            typ = last_typ
        end

        if typ == "binary" then
            local _, err = sock:send(data)
            if err then
                ngx.log(ngx.ERR, "failed to send to mbbsd: ", err)
                sock:close()
                return ngx.exit(555)
            end
        elseif typ == "close" then
            sock:close()
            local bytes, err = ws:send_close(1000, "bye")
            if err then
                ngx.log(ngx.ERR, "failed to send the close frame: ", err)
            end
            ngx.log(ngx.INFO, "closing websocket")
            return
        elseif typ == "ping" then
            local _, err = ws:send_pong(data)
            if err then
                ngx.log(ngx.ERR, "failed to send pong: ", err)
                sock:close()
                return ngx.exit(444)
            end
        elseif typ == "pong" then
            -- discard
        else
            ngx.log(ngx.INFO, "received frame of type ", typ)
        end

        last_typ = typ
    end
end

local function sock2ws(sock, ws)
    while true do
        sock:settimeout(30*60*1000)
        local data, err = sock:receiveany(1024)

        if not data then
            ws:send_close(1000, "bbs died")
            ngx.log(ngx.ERR, "failed to recv from mbbsd: ", err)
            return ngx.exit(444)
        else
            if #data > 0 then
                local bytes, err = ws:send_binary(data)
                if not bytes then
                    ngx.log(ngx.ERR, "failed to send a binary frame: ", err)
                    sock:close()
                    return ngx.exit(444)
                end
            end
        end
    end
end

-- check_origin()
-- need better ACL
local ws = start_websocket_server()
local sock = connect_mbbsd()
ngx.log(ngx.INFO, "client connect over websocket, ",
    ngx.var.server_name, ":", ngx.var.server_port, " ", ngx.var.server_protocol)
ngx.thread.spawn(ws2sock, ws, sock)
ngx.thread.spawn(sock2ws, sock, ws)
