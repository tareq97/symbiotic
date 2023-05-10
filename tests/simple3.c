#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
  
int main(int argc, char *argv[]) 
{ 
       int i = 6;
       int  *buffer = malloc(5 * sizeof(int));
       buffer[i] = 10;
       return 0; 
} 