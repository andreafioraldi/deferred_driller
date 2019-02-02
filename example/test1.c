#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#ifdef __DRILLER
void driller_init();
#endif

int main(int argc, char** argv) {

    char buf[100]; 
    memset(buf, 0, 100);

    sleep(10);
    
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
#ifdef __DRILLER
    driller_init();
#endif
    
    read(0, buf, 100);
    
    fprintf(stderr, "%s\n", buf);
    
    if(strncmp(buf, "pippo", 5) == 0) {
        if(strncmp((char*)buf +6, "franco", 6) == 0) {
            int i;
            int s = 0;
            for(i = 0; i < 12; ++i)
                s += buf[i];
            if(s == 1217)
                abort();
        }
    }

  return 0;

}
