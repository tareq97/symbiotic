#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
  
int main(int argc, char *argv[]) 
{ 
       int i = 6;
       char *buffer = malloc(5);
       buffer[i] = 'a';
       return 0; 
} 