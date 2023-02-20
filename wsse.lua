local setmetatable = setmetatable

local _M = require('apicast.policy').new('wsse', '0.1')
local mt = { __index = _M }


function _M.new(config)
        file = io.open("/tmp/config.out", "a")
        io.output(file)
        io.write(tostring(config.wsseUsername))
        io.close(file)

        wsseUsername = config.wsseUsername
        wssePassword = config.wssePassword
   return setmetatable({}, mt)
end

-- function _M.new(config)
--   local self = new(config)
-- 
--   if config then
--     self.wsse = {
--       wsseUsername = config.wsseUsername,
--       wssePassword = config.wssePassword,
--     }
--   else
--     self.wsse = {}
--   end
-- 
--   return self
--   -- return setmetatable({}, mt)
-- end

function _M:init()
  -- do work when nginx master process starts
end

function _M:init_worker()
  -- do work when nginx worker process is forked from master
end

function _M:rewrite()
        wsseSecurityHeader = [[
                <soapenv:Header>
                        <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                                <wsse:UsernameToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" wsu:Id="UsernameToken-z5ijcZEytMhncDVCTY6J7Q22" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                                        <wsse:Username>
                                ]] .. wsseUsername .. [[
                                                                                </wsse:Username>
                                        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">
                                ]] .. wssePassword .. [[ 
                                                                        </wsse:Password>
                                </wsse:UsernameToken>
                        </wsse:Security>
                </soapenv:Header>
        ]]

        -- Load http body into memory
        ngx.req.read_body()

        body = ngx.req.get_body_data()
        pos = string.find(body,"<soapenv:Body>")
        body = string.sub(body,0, pos-1) .. wsseSecurityHeader .. string.sub(body,pos)

        -- Write the content of the body to disk (Debug puprose)
        file = io.open("/tmp/body_out.lua", "a")
        io.output(file)
        io.write(body)
        io.close(file)

        ngx.req.set_body_data(body)
end


function _M:access()
  -- ability to deny the request before it is sent upstream
end

function _M:content()
  -- can create content instead of connecting to upstream
end

function _M:post_action()
  -- do something after the response was sent to the client
end

function _M:header_filter()
  -- can change response headers
end

function _M:body_filter()
  -- can read and change response body
  -- https://github.com/openresty/lua-nginx-module/blob/master/README.markdown#body_filter_by_lua
end

function _M:log()
  -- can do extra logging
end

function _M:balancer()
  -- use for example require('resty.balancer.round_robin').call to do load balancing
end

return _M
