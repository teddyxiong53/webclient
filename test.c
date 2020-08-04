#include "mylog.h"

int main(int argc, char const *argv[])
{
    if(argc < 2) {
        myloge("usage: ./test get/post [args]");
        return -1;
    }
    if(strcmp(argv[1], "get") == 0) {
        webclient_get_test(argc-1, argv+1);
    } else if(strcmp(argv[1], "post") == 0) {
        webclient_post_test(argc-1, argv+1);
    }

    return 0;
}
