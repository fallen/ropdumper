#include <bfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int verbose;

void gadget_guessing(bfd *fd, asection *p, unsigned char *data, unsigned long i)
{

return ;

}

void analyze_section(bfd *fd, asection *p)
{
	unsigned long i;
	unsigned char *data;

	data = malloc(bfd_section_size(fd, p));
	if (data == NULL)
	{
		printf("Failed to allocate memory\n");
		return;
	}

	bfd_get_section_contents(fd, p, data, 0, bfd_section_size(fd, p));

	for (i = 0 ; i < bfd_section_size(fd, p) ; ++i)
	{
		if (verbose)
			printf("%02X ", data[i]);
		if (data[i] == 0xC3)
		{
		// We found a ROP gadget
			gadget_guessing(fd, p, data, i);
			printf("[+] <0x%08" BFD_VMA_FMT "x> ROP : \n", bfd_section_vma(fd, p) + i);
		}
	}
	printf("\n\n");
}

int main(int argc, char ** argv)
{
	bfd *fd;
	asection *p;
	char *envstr;

	verbose = 0;

	bfd_init();

	if (argc > 1)
	{
		printf("Opening: %s\n", argv[1]);
	} else {
		printf("usage: %s <file>\n", argv[0]);
		exit(1);
	}

	envstr = getenv("VERBOSE");
	if (envstr != NULL && strcmp(envstr, "1") == 0)
		verbose = 1;

	if (access(argv[1], R_OK) != 0)
	{
		printf("Cannot open %s in read-only\n", argv[1]);
		perror("access");
		exit(1);
	}

	fd = bfd_openr(argv[1], NULL);

	if (fd == NULL)
	{
		printf("Cannot open %s with lib BFD\n", argv[1]);
		exit(1);
	}

	if (!bfd_check_format(fd, bfd_object))
	{
		printf("Cannot detect binary format of file %s\n", argv[1]);
		exit(1);
	}

	for (p = fd->sections ; p != NULL ; p = p->next)
	{
		bfd_vma base_addr = bfd_section_vma(fd, p);
		bfd_size_type size = bfd_section_size(fd, p);
		const char *name = bfd_section_name(fd, p);
		flagword flags = bfd_get_section_flags(fd, p);

		printf("[%s] Section %s @ 0x%08" BFD_VMA_FMT "x len : %d\n", flags & SEC_CODE ? "+" : "-", name, base_addr, (unsigned int)size);

		if (flags & SEC_CODE)
			analyze_section(fd, p);

	}

	return 0;
}
