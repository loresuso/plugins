#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <chrono>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include "hash_calculator.h"

#define HASHING_CHUNK_SIZE 32 * 1024 * 1024
#define MAX_DIGEST_LEN SHA256_DIGEST_LENGTH

int64_t hash_calculator::checksum(const std::string &filename, hash_type type, std::string *hash)
{
	uint64_t size;
	struct stat s;
	MD5_CTX cmd5;
	SHA256_CTX csha;
	unsigned char digest[MAX_DIGEST_LEN];

	int fd = open(filename.c_str(), O_RDONLY);
	if (fd == -1)
	{
		return -errno;
	}

	//
	// Get the size of the file
	//
	int fsres = fstat(fd, &s);
	if (fsres == -1)
	{
		close(fd);
		return -errno;
	}
	size = s.st_size;

	//
	// Map the file into memory. Memory mapping the file instead of reading it
	// has multiple benefits:
	// - it minimizes stack memory usage and avoids memory allocations
	// - it makes the hashing code simpler
	// - it allows to generate less system calls, and therefore pollute less the
	//   activity of the system
	//
	// note: mmap can be risky on 32 bits systems, you can end up exhausting virtual
	// memory easily. Furthermore, always remember to munmap.
	uint8_t *filebuf = (uint8_t *)mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(filebuf == MAP_FAILED)
	{
		return -errno;
	}

	(type == HT_SHA256) ? SHA256_Init(&csha) : MD5_Init(&cmd5);

	uint64_t pos = 0;
	for (pos = 0; pos + HASHING_CHUNK_SIZE < size; pos += HASHING_CHUNK_SIZE)
	{
		if(type == HT_SHA256)
			SHA256_Update(&csha, filebuf + pos, HASHING_CHUNK_SIZE);
		else 
			MD5_Update(&cmd5, filebuf + pos, HASHING_CHUNK_SIZE);
	}

	if(type == HT_SHA256)
	{
		SHA256_Update(&csha, filebuf + pos, size - pos);
		SHA256_Final(digest, &csha);
	}
	else
	{
		MD5_Update(&cmd5, filebuf + pos, size - pos);
		MD5_Final(digest, &cmd5);
	}

	close(fd);
	munmap(filebuf, size);

	//
	// Convert the binary hash into a human-readable string
	//
	char tmps[3];
	tmps[2] = 0;
	uint32_t digest_len = (type == HT_SHA256) ? SHA256_DIGEST_LENGTH : MD5_DIGEST_LENGTH;
	for (uint32_t j = 0; j < digest_len; j++)
	{
		sprintf(tmps, "%02x", digest[j]);
		(*hash) += tmps;
	}

	return 0;
}
