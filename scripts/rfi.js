window.onload = function() {
};

function RFI(ip, port, remotes, local)
{
	if(!window.WebSocket)
	{
		window.WebSocket = window.WebSocket || window.MozWebSocket;
	}
	this.ip = ip || location.host;
	this.port = port || 80;
	this.ip = 'ws://' + this.ip + ':' + this.port;
	this.protocol = 'kek-protocol';
	this.websocket = new WebSocket(this.ip, this.protocol);
	if(ip == null)
	{
		this.ip 
	}
	for(var remote in remotes)
	{
		var r = remotes[remote];
		this[r] = function(){ this.call(r, arguments); };
	}

	this.websocket.onopen = function () {
		$('h1').css('color', 'green');
	};

	this.websocket.onclose = function () {
		$('h1').css('color', 'red');
	};

	this.websocket.onerror = function () {
		$('h1').css('color', 'red');
	};

	this.websocket.onmessage = function (message) {
		console.log(message.data);
		$('div').append($('<p>', { text: message.data }));
	};

	$('button').click(function(e) {
		e.preventDefault();
		websocket.send($('input').val());
		$('input').val('');
	});
};

RFI.prototype.call = function(name, args)
{
	alert("calling " + name + " with " + JSON.stringify(args));
};
