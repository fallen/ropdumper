/*
 * Author: Yann Sionneau <yann.sionneau@gmail.com>
 * COPYRIGHT (C) 2012 Yann Sionneau
 * License: BSD
 */

#include <bfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef DEBUG_ENABLED
#define debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#define READ_PIPE 0
#define WRITE_PIPE 1

#define min(a,b) ( (a) > (b) ? (b) : (a) )

int verbose;
char *bin_filename;
unsigned int rop_found;
unsigned int hidden_rop_found;

char *exec_command(char *cmd)
{

	char *command_output;
	int pipefd[2];
	int pid;
	ssize_t size;
	ssize_t total_read;
	ssize_t output_size;

	debug("Executing: %s\n", cmd);

	if (pipe(pipefd) != 0)
		perror("Error, cannot create pipe to communicate with child process");

	pid = fork();

	if (pid == 0)
	{
	/* This is the child */
		int ret = dup2(pipefd[WRITE_PIPE], fileno(stdout));
		close(pipefd[READ_PIPE]);

		if (ret != fileno(stdout))
		{
			printf("Error: cannot close stdout and write to the pipe instead\n");
			perror("dup2");
			exit(1);
		}
		execl("/bin/bash", "bash", "-c", cmd, NULL);
		fprintf(stderr, "Error: cannot execute command %s\n", cmd);
		exit(1);
	} else if (pid == -1)
	{
		printf("Cannot fork to execute cmd %s\n", cmd);
		exit(1);
	}

	close(pipefd[WRITE_PIPE]);

	output_size = 1024;
	command_output = malloc(output_size);
	command_output[0] = '\0';
	if (command_output == NULL)
	{
		printf("Cannot allocate memory\n");
		exit(1);
	}

	total_read = 0;
	while ( (size = read(pipefd[READ_PIPE], command_output + total_read, output_size - total_read - 1)) > 0)
	{
		total_read += size;
		debug("Read: %d (total: %d)\n", size, total_read);
		if (total_read == output_size - 1)
		{
			output_size += 1024;
			command_output = realloc(command_output, output_size);
			if (command_output == NULL)
			{
				printf("Cannot allocate memory\n");
				exit(1);
			}
		}
	}

	command_output[total_read] = '\0';
	close(pipefd[READ_PIPE]);

	debug("[%p] => %s\n", command_output, command_output);

	return command_output;
}

void gadget_guessing(bfd *fd, asection *p, unsigned char *data, unsigned long i)
{
	char cmd[1024];
	char *out;
	unsigned int len;

	snprintf(cmd, 1024, "objdump -D %s | grep \"%" BFD_VMA_FMT "x:\" | cut -f3", bin_filename, bfd_section_vma(fd, p) + i);
	out = exec_command(cmd);

	if (strncmp("ret", out, strlen("ret")) == 0)
	{
		printf("ROP gadget found @ %08" BFD_VMA_FMT "x\n", bfd_section_vma(fd, p) + i);
		rop_found++;
		free(out);
		return;
	} else {
		if (verbose)
			printf("Hidden ROP gadget may be found @ %08" BFD_VMA_FMT "x, investigating...\n", bfd_section_vma(fd, p) + i);
	}

	free(out);

	for (len = 2 ; len <= min(50, i) ; ++len)
	{
		signed int j;

		snprintf(cmd, 1024, "echo -ne \"");

		for (j = len - 1; j >= 0 ; --j)
		{
			if (data[i-j] == 0x0)
			{
				debug("Found a NULL (0x00) byte in the ROP sequence, aborting\n");
				return;
			}
			snprintf(cmd + strlen(cmd), 1024 - strlen(cmd), "\\x%02X", data[i-j]);
		}

		snprintf(cmd + strlen(cmd), 1024 - strlen(cmd), "\" > data.bin");
		out = exec_command(cmd);
		free(out);

		snprintf(cmd, 1024, "objdump -m i386 -b binary -D data.bin | tail -n1 | cut -f3");
		out = exec_command(cmd);

		if (strncmp("ret", out, strlen("ret")) != 0)
		{
			debug("Not ending with ret, skipping\n");
			continue;
		}

		free(out);
		snprintf(cmd, 1024, "objdump -m i386 -b binary -D data.bin | cut -f3 | grep '\\.byte'");
		out = exec_command(cmd);
		if (strstr(out, ".byte") != NULL)
		{
			debug("Found .byte, invalid assembly instruction, skipping\n");
			continue;
		}
		free(out);

		snprintf(cmd, 1024, "objdump -m i386 -b binary -D data.bin | cut -f3 | grep '(bad)'");
		out = exec_command(cmd);
		if (strstr(out, "(bad)") != NULL)
		{
			debug("Found (bad), invalid assembly instruction, skipping\n");
			continue;
		}
		free(out);

		snprintf(cmd, 1024, "objdump -m i386 -b binary -D data.bin | cut -f3 | grep 'internal disassembler error'");
		out = exec_command(cmd);
		if (strstr(out, "internal disassembler error") != NULL)
		{
			debug("Disassembler could not disassemble this ROP gadget, skipping\n");
			continue;
		}
		free(out);

		snprintf(cmd, 1024, "objdump -m i386 -b binary -D data.bin | grep -A100 '<.data>:' | grep -v '<.data>:'");
		out = exec_command(cmd);

		printf("Found hidden ROP gadget : \n%s\n", out);
		hidden_rop_found++;
		rop_found++;
		free(out);

	}


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
		if (data[i] == 0xC3)
		{
		// We found a ROP gadget
			printf("[+] <0x%08" BFD_VMA_FMT "x> ROP : \n", bfd_section_vma(fd, p) + i);
			gadget_guessing(fd, p, data, i);
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

	bin_filename = malloc(strlen(argv[1]) + 1);
	strcpy(bin_filename, argv[1]);

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

	rop_found = 0;
	hidden_rop_found = 0;

	for (p = fd->sections ; p != NULL ; p = p->next)
	{
		bfd_vma base_addr = bfd_section_vma(fd, p);
		bfd_size_type size = bfd_section_size(fd, p);
		const char *name = bfd_section_name(fd, p);
		flagword flags = bfd_get_section_flags(fd, p);

		if ( (flags & SEC_CODE) || verbose)
			printf("[%s] Section %s @ 0x%08" BFD_VMA_FMT "x len : %d\n", flags & SEC_CODE ? "+" : "-", name, base_addr, (unsigned int)size);

		if (flags & SEC_CODE)
			analyze_section(fd, p);

	}

	free(bin_filename);

	printf("===========================\n\n");
	printf("Total found ROP gadgets: %d\n", rop_found);
	printf("Number of hidden ROP gadgets: %d/%d\n", hidden_rop_found, rop_found);

	return 0;
}
