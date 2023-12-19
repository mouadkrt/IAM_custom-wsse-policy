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

function matchUnknownNamespaceTag(xmlString, tagName)
    --local pattern = "<(%/?)([^>]+)>"
    local pattern = "<(%/?)([^>]+)%s*>"
    local matches = {}
    local startPos, endPos = 1, 1
    for slash, foundTag in xmlString:gmatch(pattern) do
        local pureTag = foundTag:gsub("%s+$", ""):gsub("[^:]+:", "") -- remove any trainling spaces , Removing namespace prefix
        if pureTag == tagName then
             _, _, ns = foundTag:find("^(.-):") -- store namespace value for later use
           -- slah is either empty for  "opening" tags or ="/" for  "closing" tags
           
            local tagStart, tagEnd = xmlString:find(slash .. foundTag, startPos)
            if tagStart and tagEnd then
                table.insert(matches, {
                    tag = foundTag,
                    slash = slash,
                    startPos = tagStart -1,
                    endPos = tagEnd + 1,
                    ns = ns
                })
            end
        end
    end
    return matches
end
 
function replaceBetween(originalString, startPos, endPos, replacement)
    local prefix = string.sub(originalString, 1, startPos - 1)  -- Extract the substring before startPos
    local suffix = string.sub(originalString, endPos + 1)       -- Extract the substring after endPos
    return prefix .. replacement .. suffix                       -- Concatenate the parts with replacement
end

function _M:rewrite()
        wsseSecurityHeader = [[
                        <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                                <wsse:UsernameToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" wsu:Id="UsernameToken-z5ijcZEytMhncDVCTY6J7Q22" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                                        <wsse:Username>]]..wsseUsername..[[</wsse:Username>
                                        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">]]..wssePassword..[[</wsse:Password>
                                </wsse:UsernameToken>
                        </wsse:Security>
        ]]

		-- Load http body into memory
			ngx.req.read_body()
			body = ngx.req.get_body_data()
		
		-- Remove any existing soap header tag (and its content) :
			soapXML = body
			soapXmlLower = string.lower(body)
			local tagName = "Header" --string.lower("Header") -- lowercase of the tag to be detected
			local matchedTags = matchUnknownNamespaceTag(soapXmlLower, tagName)
			 
			-- Print matched tags with their types
			if next(matchedTags) then
				for _, tagInfo in ipairs(matchedTags) do
				   --print("Tag:", tagInfo.slash .. tagInfo.tag)
				   --print("Start Position:", tagInfo.startPos)
				   --print("End Position:", tagInfo.endPos)
				  
				   if tagInfo.slash == "" then
					   pos1 = tagInfo.startPos
					   headerNS = tagInfo.ns
					else
					   pos2 = tagInfo.endPos
					end
				end
				-- print(pos1 .. " - " .. pos2)
				newBody = replaceBetween(soapXML, pos1, pos2 , "")
			else
				print("Tag " .. tagName .. " not found")
			end
			 
		-- Now insert the new Header (buit from the policy parameters) after the body tag :
			NewWsseSecurityHeader=" <" .. headerNS .. ":Header>" .. wsseSecurityHeader .. "</" .. headerNS .. ":Header> "
			local matchedTags = matchUnknownNamespaceTag(newBody, "body")
			if next(matchedTags) then
				for _, tagInfo in ipairs(matchedTags) do
					if tagInfo.slash == "" then
						pos = tagInfo.startPos-1
						newBody = string.sub(newBody,0, pos) ..  NewWsseSecurityHeader ..  string.sub(newBody,pos+1)
						break
					end
				end
			end
			 

        -- Write the content of the body to disk (Debug puprose)
        file = io.open("/tmp/body_out.lua", "a")
        io.output(file)
        io.write(newBody)
        io.close(file)

        ngx.req.set_body_data(newBody)
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
