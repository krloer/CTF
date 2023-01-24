#include <curses.h>

int main() {
	initscr();
  	cbreak();
  	noecho();
	scr_restore("101605B");
	doupdate();
	return 0;
}
