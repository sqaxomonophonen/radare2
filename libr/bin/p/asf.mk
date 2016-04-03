OBJ_ASF=bin_asf.o

STATIC_OBJ+=${OBJ_ASF}
TARGET_ASF=bin_asf.${EXT_SO}

ALL_TARGETS+=${TARGET_ASF}

${TARGET_ASF}: ${OBJ_ASF}
	${CC} $(call libname,bin_asf) -shared ${CFLAGS} \
		-o ${TARGET_ASF} ${OBJ_ASF} $(LINK) $(LDFLAGS)

