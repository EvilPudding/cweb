#include <stdio.h>

int main(FILE *fp, void *data)
{
	printf("Generating file\n");
/*%
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<script src="scripts/cweb.js"></script>
		<link rel="stylesheet" href="styles/default.css">
		<script type="text/javascript">

var cweb;
var input;
var button;
var people = [];
window.onload = function()
{
	cweb = new CWeb();
	input = document.getElementById('inp');
	button = document.getElementById('but');
	online = document.getElementById('online');
	button.onclick = function(e)
	{
		e.preventDefault();
		var value = input.value;
		cweb.emit('message', value);
		input.value = '';
	}

	cweb.on('connected', function()
	{
		cweb.on('left', function(data){
			var person;
			var i;
			for(i = 0; i < people.length; i++)
			{
				if(people[i].name == data.name)
				{
					person = people[i];
					break;
				}
			}
			if(person == null) return;

			online.removeChild(person.div);
			people.splice(i, 1);

		});
		cweb.on('joined', function(data){
			var person = {};
			person.div = document.createElement('div');
			person.div.className = 'person';
			person.div.innerHTML = data.name;
			person.name = data.name;

			online.appendChild(person.div);
			people.push(person);
		});
	});

};

		</script>
	</head>
	<body>
		<div id="online" style="position:fixed;right:0;width:100px;"></div>
		<div class="container">
			<h1>CWeb</h1>

			<form>
				<input id='inp' type="text" />
				<button id='but'>Send</button>
			</form>
		</div>
	</body>
</html> %*/
	return 1;
}
