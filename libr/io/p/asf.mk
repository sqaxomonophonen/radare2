OBJ_ASF=io_asf.o

STATIC_OBJ+=${OBJ_ASF}
TARGET_ASF=io_asf.${EXT_SO}
ALL_TARGETS+=${TARGET_ASF}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_ASF}: ${OBJ_ASF}
	${CC_LIB} $(call libname,io_asf) ${CFLAGS} -o ${TARGET_ASF} \
		${LDFLAGS} ${OBJ_ASF} ${LINKFLAGS}
