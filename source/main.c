#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <ps5/kernel.h>

/* Full PS5 notification struct (Size = 0xC30) */
typedef struct {
    int type;                // 0x00
    int req_id;              // 0x04
    int priority;            // 0x08
    int msg_id;              // 0x0C
    int target_id;           // 0x10
    int user_id;             // 0x14
    int unk1;                // 0x18
    int unk2;                // 0x1C
    int app_id;              // 0x20
    int error_num;           // 0x24
    int unk3;                // 0x28
    char use_icon_image_uri; // 0x2C
    char message[1024];      // 0x2D
    char uri[1024];          // 0x42D
    char unkstr[1024];       // 0x82D
} SceNotificationRequest;

int sceKernelSendNotificationRequest(int device, SceNotificationRequest *req, size_t size, int blocking);

void printf_notification(const char *fmt, ...)
{
    SceNotificationRequest noti;
    memset(&noti, 0, sizeof(noti));

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(noti.message, sizeof(noti.message), fmt, ap);
    va_end(ap);

    noti.type = 0;
    noti.use_icon_image_uri = 1;
    noti.target_id = -1;
    strncpy(noti.uri, "cxml://psnotification/tex_icon_system", sizeof(noti.uri) - 1);

    sceKernelSendNotificationRequest(0, &noti, sizeof(noti), 0);
    printf("%s\n", noti.message);
}

// Struct definition for /dev/rnps ioctl
struct ioctl_C0105203_args {
    void* buffer;
    int size;
    int error;
};

int rnps_decrypt_block(void* buffer, int size) {
    int handle = open("/dev/rnps", O_RDWR);
    if (handle < 0) {
        printf_notification("Failed to open /dev/rnps");
        return 0x800F1213;
    }

    struct ioctl_C0105203_args args = {
        .buffer = buffer,
        .size = size,
        .error = 0x800F1225
    };

    int error = 0;
    if (ioctl(handle, 0xC0105203, &args) < 0) {
        error = -1;
    } else {
        error = args.error;
    }

    close(handle);
    return error;
}

int decrypt(const char* input, const char* output) {
    int fd = open(input, O_RDONLY, 0);
    if (fd < 0) {
        printf_notification("Failed to open input: %s", input);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        printf_notification("Failed to stat: %s", input);
        close(fd);
        return -1;
    }

    size_t size = st.st_size;
    if (size == 0) {
        printf_notification("File empty: %s", input);
        close(fd);
        return -1;
    }

    unsigned char* buf = (unsigned char*)malloc(size);
    if (!buf) {
        printf_notification("Alloc failed (%zu bytes)", size);
        close(fd);
        return -1;
    }

    ssize_t read_bytes = read(fd, buf, size);
    close(fd);

    if (read_bytes != (ssize_t)size) {
        printf_notification("Read error: %s", input);
        free(buf);
        return -1;
    }

    int res = rnps_decrypt_block(buf, size);
    printf_notification("Decrypted res: %08X", res);

    if (res < 0) {
        free(buf);
        return res;
    }

    fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf_notification("Failed output open: %s", output);
        free(buf);
        return -1;
    }

    ssize_t written = write(fd, buf, size);
    close(fd);
    free(buf);

    printf_notification("Wrote %zd bytes to %s", written, output);
    return 0;
}

int main(int argc, char *argv[]) {

    /* Group 1 */
    /*
    decrypt("/system_ex/rnps/apps/NPXS40002/application.ps.bundle", "/data/NPXS40002.bin");
    decrypt("/system_ex/rnps/apps/NPXS40003/application.ps.bundle", "/data/NPXS40003.bin");
    */
    decrypt("/system_ex/rnps/apps/NPXS40008/application.ps.bundle", "/data/NPXS40008.bin");
    /*
    decrypt("/system_ex/rnps/apps/NPXS40009/application.ps.bundle", "/data/NPXS40009.bin");
    */
	
    /* Group 2 */
    /*
    decrypt("/system_ex/rnps/apps/NPXS40013/application.ps.bundle", "/data/NPXS40013.bin");
    decrypt("/system_ex/rnps/apps/NPXS40015/application.ps.bundle", "/data/NPXS40015.bin");
    decrypt("/system_ex/rnps/apps/NPXS40016/application.ps.bundle", "/data/NPXS40016.bin");
    */
	
    /* Group 3 */
    /*
    decrypt("/system_ex/rnps/apps/NPXS40018/application.ps.bundle", "/data/NPXS40018.bin");
    decrypt("/system_ex/rnps/apps/NPXS40021/application.ps.bundle", "/data/NPXS40021.bin");
    decrypt("/system_ex/rnps/apps/NPXS40027/application.ps.bundle", "/data/NPXS40027.bin");
    decrypt("/system_ex/rnps/apps/NPXS40032/application.ps.bundle", "/data/NPXS40032.bin");
    */

    /* Group 4 */
    /*
    decrypt("/system_ex/rnps/apps/NPXS40033/application.ps.bundle", "/data/NPXS40033.bin");
    decrypt("/system_ex/rnps/apps/NPXS40036/application.ps.bundle", "/data/NPXS40036.bin");
    decrypt("/system_ex/rnps/apps/NPXS40037/application.ps.bundle", "/data/NPXS40037.bin");
    decrypt("/system_ex/rnps/apps/NPXS40041/application.ps.bundle", "/data/NPXS40041.bin");
    */

    /* Group 5 */
    /*
    decrypt("/system_ex/rnps/apps/NPXS40046/application.ps.bundle", "/data/NPXS40046.bin");
    decrypt("/system_ex/rnps/apps/NPXS40047/application.ps.bundle", "/data/NPXS40047.bin");
    decrypt("/system_ex/rnps/apps/NPXS40063/application.ps.bundle", "/data/NPXS40063.bin");
    decrypt("/system_ex/rnps/apps/NPXS40138/application.ps.bundle", "/data/NPXS40138.bin");
    */

    /* Group 6 */
    /*
    decrypt("/system_ex/rnps/apps/NPXS40064/application.ps.bundle", "/data/NPXS40064.bin");
    decrypt("/system_ex/rnps/apps/NPXS40071/application.ps.bundle", "/data/NPXS40071.bin");
    decrypt("/system_ex/rnps/apps/NPXS40080/application.ps.bundle", "/data/NPXS40080.bin");
    decrypt("/system_ex/rnps/apps/NPXS40081/application.ps.bundle", "/data/NPXS40081.bin");
    */

    /* Group 7 */
    /*
    decrypt("/system_ex/rnps/apps/NPXS40141/base_dll.ps.bundle",    "/data/NPXS40141.base.bin");
    decrypt("/system_ex/rnps/apps/NPXS40141/host.ps.bundle",        "/data/NPXS40141.host.bin");
    decrypt("/system_ex/rnps/apps/NPXS40154/application.ps.bundle", "/data/NPXS40154.bin");
    decrypt("/system_ex/rnps/apps/NPXS40161/application.ps.bundle", "/data/NPXS40161.bin");
    decrypt("/system_ex/rnps/apps/NPXS40163/application.ps.bundle", "/data/NPXS40163.bin");
    */

    return 0;
}