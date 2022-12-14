#include <sys/stat.h>  
#include <fcntl.h>  
#include <stdlib.h>  
#include <unistd.h>  

void creat_at(char *dir_path, char *relative_path)  
{  
    int dir_fd;  
    int fd;  
    int flags;  
    mode_t mode;  

    dir_fd = open(dir_path, O_RDONLY);
    if (dir_fd < 0)   
    {  
        exit(EXIT_FAILURE);  
    }  

    flags = O_CREAT | O_TRUNC | O_RDWR;  
    mode = 0640;
    fd = openat(dir_fd, relative_path, flags, mode);  
    if (fd < 0)   
    {  
        exit(EXIT_FAILURE);  
    }  

    write(fd, "HELLO", 5);  

    close(fd);  
    close(dir_fd);  
}  

int main() { 
    creat_at("./dfd", "log.txt");  
    return 0;  
}