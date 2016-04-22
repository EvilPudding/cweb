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
window.onload = function()
{
	cweb = new CWeb();
	input = document.getElementById('inp');
	button = document.getElementById('but');
	button.onclick = function(e)
	{
		e.preventDefault();
		var value = input.value;
		cweb.emit('message', value);
		input.value = '';
	}
};

		</script>
	</head>
	<body>
		<div class="container">
			<h1>WebSockets test</h1>
			<ul>%*/

	for(int i = 0; i < 4; i++)
	{
			/*%<li>%*/
		fprintf(fp, "List item number %d!\n", i);
			/*%</li>%*/
	}

			/*%</ul>
			<form>
				<input id='inp' type="text" />
				<button id='but'>Send</button>
			</form>
		</div>
	</body>
</html> %*/
	return 1;
}
