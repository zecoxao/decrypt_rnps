#include "resolve.h"

int netdbg_sock;

void printf_notification(const char* fmt, ...) {
    SceNotificationRequest noti_buffer;

    va_list args;
    va_start(args, fmt);
    f_vsprintf(noti_buffer.message, fmt, args);
    va_end(args);

    noti_buffer.type = 0;
    noti_buffer.unk3 = 0;
    noti_buffer.use_icon_image_uri = 1;
    noti_buffer.target_id = -1;
    f_strcpy(noti_buffer.uri, "cxml://psnotification/tex_icon_system");

    f_sceKernelSendNotificationRequest(0, (SceNotificationRequest * ) & noti_buffer, sizeof(noti_buffer), 0);
}

struct ioctl_C0105203_args
{
  void* buffer;
  int size;
  int error;
};

int rnps_decrypt_block(void* buffer, int size)
{
  int handle = f_open("/dev/rnps", 2);
  if (handle < 0)
  {
    return 0x800F1213;
  }
  struct ioctl_C0105203_args args;
  args.buffer = buffer;
  args.size = size;
  args.error = 0x800F1225;
  int error;
  if (f_ioctl(handle, 0xC0105203, &args) < 0)
  {
    return -1;
  }
  else
  {
    error = args.error;
  }
  f_close(handle);
  return error;
}

int decrypt (char* input, char* output){
	int fd=f_open(input, O_RDONLY, 0777);
	
	printf_notification("open %08X", fd);
    
    unsigned char * buf = (unsigned char*) f_malloc(0x10000000);
    
    unsigned int size = f_read(fd,buf,0x10000000);
	
	printf_notification("size %08X", size);
    
    f_close(fd);
    
    int res = rnps_decrypt_block(buf,size);
	
	printf_notification("res %08X", res);

    fd = f_open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    
    int written = f_write(fd,buf,size);

	printf_notification("written %08X", written);
	
	return 0;
	
}

int payload_main(struct payload_args *args) {
    dlsym_t* dlsym = args->dlsym;
	
	int libKernel = 0x2001;

	dlsym(libKernel, "sceKernelLoadStartModule", &f_sceKernelLoadStartModule);
	dlsym(libKernel, "sceKernelDebugOutText", &f_sceKernelDebugOutText);
	dlsym(libKernel, "sceKernelSendNotificationRequest", &f_sceKernelSendNotificationRequest);
	dlsym(libKernel, "sceKernelUsleep", &f_sceKernelUsleep);
	dlsym(libKernel, "scePthreadMutexLock", &f_scePthreadMutexLock);
	dlsym(libKernel, "scePthreadMutexUnlock", &f_scePthreadMutexUnlock);
	dlsym(libKernel, "scePthreadExit", &f_scePthreadExit);
	dlsym(libKernel, "scePthreadMutexInit", &f_scePthreadMutexInit);
	dlsym(libKernel, "scePthreadCreate", &f_scePthreadCreate);
	dlsym(libKernel, "scePthreadMutexDestroy", &f_scePthreadMutexDestroy);
	dlsym(libKernel, "scePthreadJoin", &f_scePthreadJoin);
	dlsym(libKernel, "socket", &f_socket);
	dlsym(libKernel, "bind", &f_bind);
	dlsym(libKernel, "listen", &f_listen);
	dlsym(libKernel, "accept", &f_accept);
	dlsym(libKernel, "ioctl", &f_ioctl);
	dlsym(libKernel, "open", &f_open);
	dlsym(libKernel, "read", &f_read);
	dlsym(libKernel, "write", &f_write);
	dlsym(libKernel, "close", &f_close);
	dlsym(libKernel, "stat", &f_stat);
	dlsym(libKernel, "fstat", &f_fstat);
	dlsym(libKernel, "rename", &f_rename);
	dlsym(libKernel, "rmdir", &f_rmdir);
	dlsym(libKernel, "mkdir", &f_mkdir);
	dlsym(libKernel, "getdents", &f_getdents);
	dlsym(libKernel, "unlink", &f_unlink);
	dlsym(libKernel, "readlink", &f_readlink);
	dlsym(libKernel, "lseek", &f_lseek);
	dlsym(libKernel, "puts", &f_puts);
	dlsym(libKernel, "mmap", &f_mmap);
	dlsym(libKernel, "munmap", &f_munmap);
	dlsym(libKernel, "__error", &f___error);
	

	int libNet = f_sceKernelLoadStartModule("libSceNet.sprx", 0, 0, 0, 0, 0);
	dlsym(libNet, "sceNetSocket", &f_sceNetSocket);
	dlsym(libNet, "sceNetConnect", &f_sceNetConnect);
	dlsym(libNet, "sceNetHtons", &f_sceNetHtons);
	dlsym(libNet, "sceNetAccept", &f_sceNetAccept);
	dlsym(libNet, "sceNetSend", &f_sceNetSend);
	dlsym(libNet, "sceNetInetNtop", &f_sceNetInetNtop);
	dlsym(libNet, "sceNetSocketAbort", &f_sceNetSocketAbort);
	dlsym(libNet, "sceNetBind", &f_sceNetBind);
	dlsym(libNet, "sceNetListen", &f_sceNetListen);
	dlsym(libNet, "sceNetSocketClose", &f_sceNetSocketClose);
	dlsym(libNet, "sceNetHtonl", &f_sceNetHtonl);
	dlsym(libNet, "sceNetInetPton", &f_sceNetInetPton);
	dlsym(libNet, "sceNetGetsockname", &f_sceNetGetsockname);
	dlsym(libNet, "sceNetRecv", &f_sceNetRecv);
	dlsym(libNet, "sceNetErrnoLoc", &f_sceNetErrnoLoc);
	dlsym(libNet, "sceNetSetsockopt", &f_sceNetSetsockopt);

	int libC = f_sceKernelLoadStartModule("libSceLibcInternal.sprx", 0, 0, 0, 0, 0);
	dlsym(libC, "vsprintf", &f_vsprintf);
	dlsym(libC, "memset", &f_memset);
	dlsym(libC, "memalign", &f_memalign);
	dlsym(libC, "sprintf", &f_sprintf);
	dlsym(libC, "snprintf", &f_snprintf);
	dlsym(libC, "snprintf_s", &f_snprintf_s);
	dlsym(libC, "strcat", &f_strcat);
	dlsym(libC, "free", &f_free);
	dlsym(libC, "memcpy", &f_memcpy);
	dlsym(libC, "strcpy", &f_strcpy);
	dlsym(libC, "strncpy", &f_strncpy);
	dlsym(libC, "sscanf", &f_sscanf);
	dlsym(libC, "malloc", &f_malloc);
	dlsym(libC, "calloc", &f_calloc);
	dlsym(libC, "strlen", &f_strlen);
	dlsym(libC, "strcmp", &f_strcmp);
	dlsym(libC, "strchr", &f_strchr);
	dlsym(libC, "strrchr", &f_strrchr);
	dlsym(libC, "gmtime_s", &f_gmtime_s);
	dlsym(libC, "time", &f_time);
	dlsym(libC, "localtime", &f_localtime);
	dlsym(libC, "strerror", &f_strerror);
	
	int libNetCtl = f_sceKernelLoadStartModule("libSceNetCtl.sprx", 0, 0, 0, 0, 0);
	dlsym(libNetCtl, "sceNetCtlInit", &f_sceNetCtlInit);
	dlsym(libNetCtl, "sceNetCtlTerm", &f_sceNetCtlTerm);
	dlsym(libNetCtl, "sceNetCtlGetInfo", &f_sceNetCtlGetInfo);
	
	/*
	decrypt("/system_ex/rnps/apps/NPXS40002/application.ps.bundle","/data/NPXS40002.bin");
	decrypt("/system_ex/rnps/apps/NPXS40003/application.ps.bundle","/data/NPXS40003.bin");
	decrypt("/system_ex/rnps/apps/NPXS40008/application.ps.bundle","/data/NPXS40008.bin");
	decrypt("/system_ex/rnps/apps/NPXS40009/application.ps.bundle","/data/NPXS40009.bin");
	*/
	
	
	decrypt("/system_ex/rnps/apps/NPXS40013/application.ps.bundle","/data/NPXS40013.bin");
	decrypt("/system_ex/rnps/apps/NPXS40015/application.ps.bundle","/data/NPXS40015.bin");
	decrypt("/system_ex/rnps/apps/NPXS40016/application.ps.bundle","/data/NPXS40016.bin");
	
	
	/*
	
	decrypt("/system_ex/rnps/apps/NPXS40018/application.ps.bundle","/data/NPXS40018.bin");
	decrypt("/system_ex/rnps/apps/NPXS40021/application.ps.bundle","/data/NPXS40021.bin");
	decrypt("/system_ex/rnps/apps/NPXS40027/application.ps.bundle","/data/NPXS40027.bin");
	decrypt("/system_ex/rnps/apps/NPXS40032/application.ps.bundle","/data/NPXS40032.bin");
	*/
	
	/*
	decrypt("/system_ex/rnps/apps/NPXS40033/application.ps.bundle","/data/NPXS40033.bin");
	decrypt("/system_ex/rnps/apps/NPXS40036/application.ps.bundle","/data/NPXS40036.bin");
	decrypt("/system_ex/rnps/apps/NPXS40037/application.ps.bundle","/data/NPXS40037.bin");
	decrypt("/system_ex/rnps/apps/NPXS40041/application.ps.bundle","/data/NPXS40041.bin");
	*/
	
	/*
	
	decrypt("/system_ex/rnps/apps/NPXS40046/application.ps.bundle","/data/NPXS40046.bin");
	decrypt("/system_ex/rnps/apps/NPXS40047/application.ps.bundle","/data/NPXS40047.bin");
	decrypt("/system_ex/rnps/apps/NPXS40063/application.ps.bundle","/data/NPXS40063.bin");
	decrypt("/system_ex/rnps/apps/NPXS40138/application.ps.bundle","/data/NPXS40138.bin");
	*/
	
	/*
	decrypt("/system_ex/rnps/apps/NPXS40064/application.ps.bundle","/data/NPXS40064.bin");
	decrypt("/system_ex/rnps/apps/NPXS40071/application.ps.bundle","/data/NPXS40071.bin");
	decrypt("/system_ex/rnps/apps/NPXS40080/application.ps.bundle","/data/NPXS40080.bin");
	decrypt("/system_ex/rnps/apps/NPXS40081/application.ps.bundle","/data/NPXS40081.bin");
	*/
	/*
	decrypt("/system_ex/rnps/apps/NPXS40141/base_dll.ps.bundle","/data/NPXS40141.base.bin");
	decrypt("/system_ex/rnps/apps/NPXS40141/host.ps.bundle","/data/NPXS40141.host.bin");
	decrypt("/system_ex/rnps/apps/NPXS40154/application.ps.bundle","/data/NPXS40154.bin");
	decrypt("/system_ex/rnps/apps/NPXS40161/application.ps.bundle","/data/NPXS40161.bin");
	decrypt("/system_ex/rnps/apps/NPXS40163/application.ps.bundle","/data/NPXS40163.bin");
	*/
	

  return 0;
}
