LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS :=optional
LOCAL_C_INCLUDES := $(KERNEL_HEADERS)
LOCAL_CFLAGS += -DANDROID                 
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_LDLIBS :=-llog
LOCAL_MODULE:= webad
LOCAL_SRC_FILES:=main.c \
                 mnetlink.c \
		 msocket.c \
                 cjson.c
  
LOCAL_PRELINK_MODULE := false
include $(BUILD_EXECUTABLE)
