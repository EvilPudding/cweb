window.onload = function() {
};

function CWeb(ip, port)
{
	if(!window.WebSocket)
	{
		window.WebSocket = window.WebSocket || window.MozWebSocket;
	}
	this.ip = ip || location.host;
	this.port = port || 80;
	this.ip = 'ws://' + this.ip + ':' + this.port;
	this.protocol = 'cwebsockets';

	this.websocket = new WebSocket(this.ip, this.protocol);
	this.websocket.cweb = this;

	this.responses = {};
	this.events = {};
	this.ms_id = 1;

	this.websocket.onopen = function () {
		this.cweb.init();
	};

	this.websocket.onclose = function () {
		this.cweb.called("disconnected", null);
	};

	this.websocket.onerror = function () {
		this.cweb.called("error", null);
	};

	this.websocket.onmessage = function(message) {
		var data = JSON.parse(message.data);
		var ms_id = message.id;
		this.cweb.called(data.event, data.data, function(res) {
			this.emit("cweb_cb", {"cbi": ms_id, "data":res});
		});
	};

};

CWeb.prototype.init = function()
{
	var cweb = this;
	this.on("cweb_cb", function(data){
		var cb = cweb.responses[data.id];
		if(cb)
		{
			cb.call(cweb, data.data);
			cweb.responses[data.id] = null;
		}
	});
	this.called("connected", null);
}

CWeb.prototype.on = function(name, callback)
{
	this.events[name] = callback;
};

CWeb.prototype.called = function(name, data, res)
{
	var cb = this.events[name];
	if(cb) cb(data, res);
};

CWeb.prototype.emit = function(name, data, response)
{
	var ms_id = this.ms_id++;
	if(response)
	{
		this.responses[ms_id] = response;
	}
	this.websocket.send(JSON.stringify({'event':name, 'data':data, 'cbi':ms_id}));
};
