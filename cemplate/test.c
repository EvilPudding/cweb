#include "cemplate.h"

int main(FILE *fp, void *data)
{

/*%
<html> <head> </head> <body> <ul>
%*/
	for(int i = 0; i < 10; i++)
	{
		/*%<li>%*/
		fprintf(fp, "List item number %d!\n", i);
		/*%</li>%*/
	}
/*%
</ul> </body> </html>
%*/

	return 1;
}
