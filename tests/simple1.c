#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
  
int main(int argc, char *argv[]) 
{ 
       int x = 0;
       int s = 5;
       int i = 6;
       int y = 0;
       if(x != 0){
              x++;
              //something else
       }
       char *buffer = malloc(s);
       //char *buffer1 = malloc(s);
       if(y == 0){
              buffer[i] = 'a';
              //buffer1[i] = 'a'; 
       }
       return 0; 
} 