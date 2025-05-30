CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(quicly)

INCLUDE(CMakePushCheckState)
INCLUDE(CheckCSourceCompiles)
INCLUDE(deps/picotls/cmake/boringssl-adjust.cmake)
INCLUDE(deps/picotls/cmake/dtrace-utils.cmake)
INCLUDE(deps/picotls/cmake/fusion.cmake)

FIND_PACKAGE(OpenSSL REQUIRED)
BORINGSSL_ADJUST()
IF (OPENSSL_FOUND AND (OPENSSL_VERSION VERSION_LESS "1.0.2"))
    MESSAGE(FATAL "OpenSSL 1.0.2 or above is missing")
ENDIF ()

CHECK_DTRACE(${CMAKE_SOURCE_DIR}/deps/picotls/picotls-probes.d)
OPTION(WITH_DTRACE "use USDT (userspace Dtrace probes)" ${HAVE_DTRACE})
IF (WITH_DTRACE)
    MESSAGE(STATUS "Enabling USDT support")
ENDIF ()

CHECK_FUSION_PREREQUISITES()
OPTION(WITH_FUSION "whether or not to use the Fusion AES-GCM engine in the cli binary" ${WITH_FUSION_DEFAULT})

# CMake defaults to a Debug build, whereas quicly defaults to an optimized (Release) build
IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
ENDIF(NOT CMAKE_BUILD_TYPE)
SET(CMAKE_C_FLAGS "-std=c99 -Wall -g -DQUICLY_USE_TRACER=1 ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

INCLUDE_DIRECTORIES(
    ${OPENSSL_INCLUDE_DIR}
    deps/klib
    deps/picotls/include
    deps/picotest
    include
    ${CMAKE_CURRENT_BINARY_DIR})

SET(PICOTLS_OPENSSL_FILES
    deps/picotls/lib/hpke.c
    deps/picotls/lib/openssl.c
    deps/picotls/lib/pembase64.c
    deps/picotls/lib/picotls.c)

SET(QUICLY_LIBRARY_FILES
    lib/frame.c
    lib/cc-reno.c
    lib/cc-cubic.c
    lib/cc-pico.c
    lib/defaults.c
    lib/local_cid.c
    lib/loss.c
    lib/quicly.c
    lib/ranges.c
    lib/rate.c
    lib/recvstate.c
    lib/remote_cid.c
    lib/retire_cid.c
    lib/sendstate.c
    lib/sentmap.c
    lib/streambuf.c
    ${CMAKE_CURRENT_BINARY_DIR}/quicly-tracer.h)

SET(UNITTEST_SOURCE_FILES
    deps/picotest/picotest.c
    t/frame.c
    t/jumpstart.c
    t/local_cid.c
    t/loss.c
    t/lossy.c
    t/maxsender.c
    t/pacer.c
    t/ranges.c
    t/rate.c
    t/remote_cid.c
    t/retire_cid.c
    t/sentmap.c
    t/simple.c
    t/stream-concurrency.c
    t/test.c)

IF (WITH_DTRACE)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPICOTLS_USE_DTRACE=1 -DQUICLY_USE_DTRACE=1")
    DEFINE_DTRACE_DEPENDENCIES(${CMAKE_SOURCE_DIR}/deps/picotls/picotls-probes.d picotls)
    DEFINE_DTRACE_DEPENDENCIES(${CMAKE_SOURCE_DIR}/quicly-probes.d quicly)
    LIST(APPEND PICOTLS_OPENSSL_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.h)
    LIST(APPEND QUICLY_LIBRARY_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.h)
    LIST(APPEND UNITTEST_SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.h)
    IF (DTRACE_USES_OBJFILE)
        LIST(APPEND PICOTLS_OPENSSL_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.o)
        LIST(APPEND QUICLY_LIBRARY_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.o)
        LIST(APPEND UNITTEST_SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.o)
    ENDIF ()
ENDIF ()

ADD_CUSTOM_COMMAND(
    OUTPUT quicly-tracer.h
    COMMAND ${PROJECT_SOURCE_DIR}/misc/probe2trace.pl -a tracer < ${PROJECT_SOURCE_DIR}/quicly-probes.d > ${CMAKE_CURRENT_BINARY_DIR}/quicly-tracer.h
    DEPENDS quicly-probes.d misc/probe2trace.pl
    VERBATIM)

ADD_LIBRARY(quicly ${QUICLY_LIBRARY_FILES})
TARGET_LINK_LIBRARIES(quicly LINK_PUBLIC m)

SET(CLI_FILES ${PICOTLS_OPENSSL_FILES} ${QUICLY_LIBRARY_FILES} src/cli.c)
SET(CLI_COMPILE_FLAGS "")
IF (WITH_FUSION)
    LIST(APPEND CLI_FILES deps/picotls/lib/fusion.c)
    SET(CLI_COMPILE_FLAGS "-mavx2 -maes -mpclmul -mvaes -mvpclmulqdq -DQUICLY_HAVE_FUSION=1 ${CLI_COMPILE_FLAGS}")
ENDIF ()
ADD_EXECUTABLE(cli ${CLI_FILES})
SET_TARGET_PROPERTIES(cli PROPERTIES COMPILE_FLAGS "${CLI_COMPILE_FLAGS}")
TARGET_LINK_LIBRARIES(cli ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS} m)

ADD_EXECUTABLE(test.t ${PICOTLS_OPENSSL_FILES} ${UNITTEST_SOURCE_FILES})
TARGET_LINK_LIBRARIES(test.t quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(simulator ${PICOTLS_OPENSSL_FILES} ${QUICLY_LIBRARY_FILES} t/simulator.c)
TARGET_LINK_LIBRARIES(simulator ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS} m)

ADD_EXECUTABLE(examples-echo ${PICOTLS_OPENSSL_FILES} examples/echo.c)
TARGET_LINK_LIBRARIES(examples-echo quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(cpep-clt ${PICOTLS_OPENSSL_FILES} cpep/simple-client.c cpep/common.c)
TARGET_LINK_LIBRARIES(cpep-clt quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(dummy-clt ${PICOTLS_OPENSSL_FILES} cpep/dummy-client.c cpep/common.c)
TARGET_LINK_LIBRARIES(dummy-clt quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(cpep-srv ${PICOTLS_OPENSSL_FILES} cpep/simple-server.c cpep/common.c)
TARGET_LINK_LIBRARIES(cpep-srv quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS}) 

ADD_EXECUTABLE(udpfw t/udpfw.c)

ADD_CUSTOM_TARGET(check env BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} WITH_DTRACE=${WITH_DTRACE} prove --exec "sh -c" -v ${CMAKE_CURRENT_BINARY_DIR}/*.t t/*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS cli udpfw test.t)

ADD_CUSTOM_TARGET(format clang-format -i `git ls-files include lib src t | egrep '\\.[ch]$$'`)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "-D_GNU_SOURCE -pthread ${CMAKE_C_FLAGS}")
ENDIF ()

IF (BUILD_FUZZER)
    MESSAGE(STATUS "************* Making the fuzzer")
    IF(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "The fuzzer needs clang as a compiler")
    ENDIF()
    ADD_EXECUTABLE(quicly-fuzzer-packet fuzz/packet.cc ${PICOTLS_OPENSSL_FILES})
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS}")
    IF (OSS_FUZZ)
        # Use https://github.com/google/oss-fuzz compatible options
        SET(LIB_FUZZER FuzzingEngine)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
        TARGET_LINK_LIBRARIES(quicly-fuzzer-packet quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS})
    ELSEIF (USE_CLANG_RT)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -fsanitize-coverage=edge,indirect-calls")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -fsanitize-coverage=edge,indirect-calls")
        TARGET_LINK_LIBRARIES(quicly-fuzzer-packet quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS})
    ELSE()
        SET(LIB_FUZZER "${CMAKE_CURRENT_BINARY_DIR}/libFuzzer.a")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link")
        ADD_CUSTOM_TARGET(libFuzzer ${CMAKE_CURRENT_SOURCE_DIR}/misc/build_libFuzzer.sh WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        ADD_DEPENDENCIES(quicly-fuzzer-packet libFuzzer)
        TARGET_LINK_LIBRARIES(quicly-fuzzer-packet quicly ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS} ${LIB_FUZZER})
    ENDIF(OSS_FUZZ)
ENDIF()
