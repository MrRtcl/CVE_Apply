## Mercury MER1200 Router v1.0.1 RCE

the function <u>add_server_service</u>  in /usr/lib/lua/luci/controller/admin/pptp_server.lua

```lua
function add_server_service(http_form)
	local content = luci.json.decode(http_form.data)
	content = content.params.new
	local name = nil
	local getRet = {}

	--check the data legality
	if not check_option_legality(content, "server") then
		return false,err.ERR_VPN_INVALID_PARAMS
	end
	
	if not content.server then
		content.server = _get_available_servername()
	else
		uci_r:foreach("pptp-server","pns",
			function(section)
				if section["server"] == content.server then
					gdb("server name conflicted")
					return false,err.ERR_COM_TABLE_ITEM_UCI_ADD
				end
			end
		)
	end
	--check if the bind WAN exists in config file
	uci_r:foreach("pptp-server","pns",
		function(section)
			if section["bindif"] == content.bindif then
				gdb("service already exists in this wan interface")
				return false,err.ERR_COM_TABLE_ITEM_UCI_ADD
			end
		end
	)
	local ret=uci_r:section("pptp-server","pns",nil,content)
	if not ret then 
		return false,err.ERR_COM_TABLE_ITEM_UCI_ADD
	end
	
	if not uci_r:commit("pptp-server") then
		return false,err.ERR_COM_UCI_COMMIT
	end

	local pptp_cmd=string.format("lua /lib/pptp/pptp_process_manager.lua")			
	sys.fork_call(pptp_cmd)	

	--directly pass those params to shell
	local cmd = string.format("/lib/pptp/add-service.sh %s %s %s %s %s",content.server,content.bindif,content.enable,content.mppeencryption,content.authtype)
	sys.fork_exec(cmd)
	ifs.update_if_reference(content.bindif,1)
	dhcp_m.lan_settings_set_manual_mode()
	userconfig.cfg_modify();
	return content
end
```

In lines 397,398

```lua
	local cmd = string.format("/lib/pptp/add-service.sh %s %s %s %s %s",content.server,content.bindif,content.enable,content.mppeencryption,content.authtype)
	sys.fork_exec(cmd)
```

Directly splice parameters content.server to the command.

In line 359

```lua
	if not check_option_legality(content, "server") then
		return false,err.ERR_VPN_INVALID_PARAMS
	end
```

function check_option_legality

```lua
	elseif data_type == "server" then
		if data.authtype ~= "local" then
			return false
		end

		if not dt_m.iface(data.bindif) then
			return false
		end

		if not dt_m.bool(data.enable) then
			return false
		end

		if not dt_m.bool(data.mppeencryption) then
			return false
		end
	end
```

There is no judgment on the parameters server, which results in that when adding a PPTP server, the command can be executed by manually changing the package.

![QQ20200324-233142@2x](https://tva1.sinaimg.cn/large/00831rSTgy1gd9uy36hajj32ig0q0wi4.jpg)

![QQ20200324-233205@2x](https://tva1.sinaimg.cn/large/00831rSTgy1gd9uxw2wz7j30oi094gp4.jpg)

The id command was successfully executed and the permission is root

