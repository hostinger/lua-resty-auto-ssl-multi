local CAA_record = 257

return function(auto_ssl_instance, ssl_provider, domain)
  if not auto_ssl_instance:get("dns_check_before_cert") then
    return true
  end

  local ip_pass = false
  local caa_pass = false

  local resolver = require "resty.dns.resolver"
  local r, err = resolver:new{
    nameservers = {"8.8.8.8", "8.8.4.4", "1.1.1.1" },
    retrans = 3,  -- 3 retransmissions on receive timeout
    timeout = 2000,  -- 2 sec
    no_random = false, -- always start with first nameserver
  }

  if not r then
      ngx.log(ngx.ERR, "failed to instantiate the dns resolver: ", err)
      return false
  end

  local answers, err, tries = r:query(domain, nil, {})
  if not answers then
      ngx.log(ngx.ERR, domain, " failed to query the DNS server: ", err)
      return false
  end

  if answers.errcode then
      ngx.log(ngx.ERR, domain, " server returned error code: ", answers.errcode,
              ": ", answers.errstr)
  end

  for i, ans in ipairs(answers) do
      ngx.log(ngx.NOTICE, ans.name, " ", ans.address or ans.cname, " type:", ans.type, " class:", ans.class, " ttl:", ans.ttl)
      for i, entry in ipairs(auto_ssl_instance:get("dns_check_hosts")) do
        if entry == ans.name or entry == ans.address or entry == ans.cname then
          ip_pass = true
          break
        end
      end
  end

  if ip_pass == false then
      ngx.log(ngx.ERR, "domain failed ip check domain ", domain, " provider ", ssl_provider)
      return false
  end

  answers, err, tries = r:query(domain, { qtype = CAA_record }, {})
  if not answers then
    ngx.log(ngx.ERR, domain, " failed to query the DNS server: ", err)
    ngx.log(ngx.ERR, "retry historie:\n  ", table.concat(tries, "\n  "))
    return false
  end

  if answers.errcode then
    ngx.log(ngx.ERR, domain, " server returned error code: ", answers.errcode,
            ": ", answers.errstr)
  end

  if #answers == 0 then
    caa_pass = true
  end

  local caa_record = auto_ssl_instance:get("ssl_provider_caa_records")[ssl_provider]
  for i, ans in ipairs(answers) do
    if ans.rdata == nil or string.find(ans.rdata, caa_record) then
      caa_pass = true
      break
    end
  end
  if caa_pass == false then
    ngx.log(ngx.ERR, "CAA check failed ", ssl_provider, " ", domain)
    return false
  else
    ngx.log(ngx.INFO, "CAA and Ip check success ", ssl_provider, " ", domain)
    return true
  end
end
