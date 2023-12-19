-- try it on https://www.jdoodle.com/execute-lua-online/

function matchUnknownNamespaceTag(xmlString, tagName)
    --local pattern = "<(%/?)([^>]+)>"
    local pattern = "<(%/?)([^>]+)%s*>"
    local matches = {}
    local startPos, endPos = 1, 1
    for slash, foundTag in xmlString:gmatch(pattern) do
        local pureTag = foundTag:gsub("%s+$", ""):gsub("[^:]+:", "") -- remove any trainling spaces , Removing namespace prefix
        if pureTag == tagName then
            
           -- slah is either empty for  "opening" tags or ="/" for  "closing" tags
            
            local tagStart, tagEnd = xmlString:find(slash .. foundTag, startPos)
            if tagStart and tagEnd then
                table.insert(matches, {
                    tag = foundTag,
                    slash = slash,
                    startPos = tagStart -1,
                    endPos = tagEnd + 1
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

soapXML = [[
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tic="http://ticket.degroupage.atos.ma/">
   <     r:Headerr>
      <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
         <wsse:UsernameToken>
            <wsse:Username>userrrr</wsse:Username>
            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">pasworddd</wsse:Password>
         </wsse:UsernameToken>
      </wsse:Security>
   </soapenvYY:Headerr   >
                <soapenv:Body>
      <tic:createTicket>
         <!--Optional:-->
         <nd>0529102356</nd>
      </tic:createTicket>
   </soapenv:Body>
</soapenv:Envelope>
]]

soapXML = string.lower(soapXML)
local tagName = string.lower("Headerr") -- lowercase of the tag to be detected
local matchedTags = matchUnknownNamespaceTag(soapXML, tagName)

-- Print matched tags with their types
if next(matchedTags) then
    for _, tagInfo in ipairs(matchedTags) do
       -- print("Tag:", tagInfo.slash .. tagInfo.tag)
       -- print("Start Position:", tagInfo.startPos)
       -- print("End Position:", tagInfo.endPos)
       
       if tagInfo.slash == "" then
           pos1 = tagInfo.startPos
        else
           pos2 = tagInfo.endPos
        end
end
    print(pos1 .. " - " .. pos2)
    newBody = replaceBetween(soapXML, pos1, pos2 , "") 
else
    print("Tag " .. tagName .. " not found")
end

print("New soapXML payload after removing any <" .. tagName .. "> tags (and its content) :")
print(newBody)  
