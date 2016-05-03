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

	this.events = {};


	this.websocket.onopen = function () {
		this.cweb.called("connected", null);
	};

	this.websocket.onclose = function () {
		this.cweb.called("disconnected", null);
	};

	this.websocket.onerror = function () {
		this.cweb.called("error", null);
	};

	this.websocket.onmessage = function(message) {
		console.log(message);
		var data = JSON.parse(message.data);
		this.cweb.called(data.event, data.data);
	};
};

CWeb.prototype.on = function(name, callback)
{
	this.events[name] = callback;
};

CWeb.prototype.called = function(name, data)
{
	var cb = this.events[name];
	if(cb) cb(data);
};

CWeb.prototype.emit = function(name, data)
{
	this.websocket.send(JSON.stringify({'event':name, 'data':data}));
};
