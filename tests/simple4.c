#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
  
int main(int argc, char *argv[]) 
{ 
       int i = 6;
       int s = 5; 
       int  *buffer = malloc(s * sizeof(int));
       //if(x <= 10 && i <=5 )
       //if(i<=5)
       buffer[i] = 10;
       return 0; 
} 