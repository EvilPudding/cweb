#include <stdio.h>

int main(FILE *fp, void *data)
{
/*%
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js"></script>
		<script src="scripts/rfi.js"></script>
		<script type="text/javascript">

var rfi;
window.onload = function() {
	rfi = new RFI(null, null, ["print_number"]);
	rfi.print_number(10);
};

		</script>
	</head>
	<body>
		<h1>WebSockets test</h1>
		<ul>%*/

	for(int i = 0; i < 10; i++)
	{
		/*%<li>%*/
		fprintf(fp, "List item number %d!\n", i);
		/*%</li>%*/
	}

		/*%</ul>
		<form>
			<input type="text" />
			<button>Send</button>
		</form>
		<div></div>
	</body>
</html> %*/
	return 1;
}