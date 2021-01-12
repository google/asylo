# Description:
#   Redis (http://redis.io) is an open source, advanced key-value store.
#   This is a bazel BUILD file for Redis 6.0.9.

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
    features = [
        "-layering_check",
        "-parse_headers",
    ],
)

licenses(["notice"])  # BSD

# Redefine the redis zcalloc function name to avoid collisions with zlib, which
# is a dependency of protobuf.
ZCALLOC_COPT = ["-Dzcalloc=redis_zcalloc"]

# Libraries for Redis deps.

cc_library(
    name = "hiredis_lib",
    srcs = ["deps/hiredis/" + filename for filename in [
        "async.c",
        "async.h",
        "async_private.h",
        "dict.c",
        "dict.h",
        "fmacros.h",
        "hiredis.c",
        "hiredis.h",
        "net.c",
        "net.h",
        "read.c",
        "read.h",
        "sds.h",
        "sdsalloc.h",
        "sockcompat.h",
        "win32.h",
    ]],
    copts = [
        "-std=c99",
        "-Wno-unused-function",
        # The definition of macro "__redis_strerror_r" in "hiredis.h" with
        # "GNU_SOURCE" defined has a bug that causes bazel compilation errors
        # when used by "__redisSetErrorFromErrno()" in "net.c".
        # Also the behavior they are trying to correct for "GNU_SOURCE" case
        # does not apply to us even though we specifiy "GNU_SOURCE", so it still
        # results in  the correct functionality.
        "-U_GNU_SOURCE",
    ] + ZCALLOC_COPT,
    textual_hdrs = ["deps/hiredis/dict.c"],
)

cc_library(
    name = "linenoise_lib",
    srcs = ["deps/linenoise/" + filename for filename in [
        "linenoise.c",
        "linenoise.h",
    ]],
)

# We use the version of Lua bundled with Redis for now, instead of depending
# on a pre-installed version. We want to make sure Redis users get a consistent
# experience, down to Lua language features. This reflects the intention of
# the Redis developers; see
# https://github.com/antirez/redis/blob/unstable/deps/README.md#lua.
cc_library(
    name = "lua_lib",
    srcs = ["deps/lua/src/" + filename for filename in [
        "fpconv.c",
        "fpconv.h",
        "lapi.c",
        "lapi.h",
        "lauxlib.c",
        "lauxlib.h",
        "lbaselib.c",
        "lcode.c",
        "lcode.h",
        "ldblib.c",
        "ldebug.c",
        "ldebug.h",
        "ldo.c",
        "ldo.h",
        "ldump.c",
        "lfunc.c",
        "lfunc.h",
        "lgc.c",
        "lgc.h",
        "linit.c",
        "liolib.c",
        "llex.c",
        "llex.h",
        "llimits.h",
        "lmathlib.c",
        "lmem.c",
        "lmem.h",
        "loadlib.c",
        "lobject.c",
        "lobject.h",
        "lopcodes.c",
        "lopcodes.h",
        "loslib.c",
        "lparser.c",
        "lparser.h",
        "lstate.c",
        "lstate.h",
        "lstring.c",
        "lstring.h",
        "lstrlib.c",
        "ltable.c",
        "ltable.h",
        "ltablib.c",
        "ltm.c",
        "ltm.h",
        "lua.h",
        "luaconf.h",
        "lualib.h",
        "lua_bit.c",
        "lua_cjson.c",
        "lua_cmsgpack.c",
        "lua_struct.c",
        "lundump.c",
        "lundump.h",
        "lvm.c",
        "lvm.h",
        "lzio.c",
        "lzio.h",
        "print.c",
        "strbuf.c",
        "strbuf.h",
    ]] + ["src/solarisfixes.h"],
    copts = [
        "-Wno-empty-body",
        "-Wno-implicit-function-declaration",
        "-Wno-unused-variable",
        "-Wno-misleading-indentation",
        # Needed to enable the cjson Lua module.
        "-DENABLE_CJSON_GLOBAL",
    ] + ZCALLOC_COPT,
)

sh_binary(
    name = "mkreleasehdr",
    srcs = ["src/mkreleasehdr.sh"],
)

genrule(
    name = "generate_release_header",
    outs = ["release.h"],
    cmd = """$(location mkreleasehdr);
             mv release.h $@""",
    tools = [":mkreleasehdr"],
)

cc_library(
    name = "redis_lib",
    srcs = ["src/" + filename for filename in [
        "acl.c",
        "adlist.c",
        "adlist.h",
        "atomicvar.h",
        "quicklist.c",
        "quicklist.h",
        "ae.c",
        "ae.h",
        "anet.c",
        "anet.h",
        "config.h",
        "crc64.h",
        "connection.c",
        "connection.h",
        "connhelpers.h",
        "debugmacro.h",
        "dict.c",
        "dict.h",
        "endianconv.h",
        "sds.c",
        "sds.h",
        "zmalloc.c",
        "latency.h",
        "listpack.h",
        "lzf.h",
        "lzfP.h",
        "lzf_c.c",
        "lzf_d.c",
        "pqsort.c",
        "pqsort.h",
        "zipmap.c",
        "zipmap.h",
        "sha1.c",
        "sha1.h",
        "sha256.c",
        "sha256.h",
        "ziplist.c",
        "rax.c",
        "rax.h",
        "rax_malloc.h",
        "release.c",
        "networking.c",
        "util.c",
        "object.c",
        "db.c",
        "redisassert.h",
        "replication.c",
        "rdb.c",
        "rdb.h",
        "tracking.c",
        "tls.c",
        "t_string.c",
        "t_list.c",
        "t_set.c",
        "t_zset.c",
        "t_hash.c",
        "config.c",
        "aof.c",
        "pubsub.c",
        "multi.c",
        "debug.c",
        "sort.c",
        "stream.h",
        "intset.c",
        "intset.h",
        "syncio.c",
        "cluster.c",
        "cluster.h",
        "crc16.c",
        "endianconv.c",
        "slowlog.c",
        "slowlog.h",
        "scripting.c",
        "bio.c",
        "bio.h",
        "rio.c",
        "rio.h",
        "rand.c",
        "rand.h",
        "memtest.c",
        "crc64.c",
        "crcspeed.c",
        "crcspeed.h",
        "bitops.c",
        "sentinel.c",
        "siphash.c",
        "notify.c",
        "setproctitle.c",
        "blocked.c",
        "solarisfixes.h",
        "hyperloglog.c",
        "latency.c",
        "server.h",
        "sparkline.c",
        "sparkline.h",
        "redismodule.h",
        "redis-check-rdb.c",
        "geo.c",
        "geo.h",
        "geohash.c",
        "geohash.h",
        "geohash_helper.c",
        "geohash_helper.h",
        "gopher.c",
        "util.h",
        "version.h",
        "ziplist.h",
        "zmalloc.h",
    ]] + ["release.h"],
    copts = [
        "-std=c99",
        "-D_GNU_SOURCE",
    ] + select({
        "@com_google_asylo//asylo": [
            # "llroundl" is used in "src/hyperloglog.c", but the arguments are
            # all doubles, therefore we use llround instead for it since it's
            # sufficent and Asylo don't currently support "llroundl".
            "-Dllroundl=llround",
        ],
        "//conditions:default": [
            # These flags are needed for bazel to compile Redis client without
            # Asylo toolchain.
            "-DSYNC_FILE_RANGE_WAIT_BEFORE=1",
            "-DSYNC_FILE_RANGE_WRITE=2",
        ],
    }) + ZCALLOC_COPT,
    includes = [
        "deps/hiredis",
        "deps/linenoise",
        "deps/lua/src",
        "src",
    ],
    linkopts = select({
        "@com_google_asylo//asylo": [],
        "//conditions:default": ["-ldl"],
    }),
    textual_hdrs = [
        "src/ae_select.c",
        "src/ae_epoll.c",
    ],
    deps = [
        ":hiredis_lib",
        ":linenoise_lib",
        ":lua_lib",
    ],
)

cc_library(
    name = "redis_main",
    srcs = [
        "deps/lua/src/lua.h",
        "deps/lua/src/luaconf.h",
        "src/ae.h",
        "src/anet.h",
        "src/asciilogo.h",
        "src/bio.h",
        "src/childinfo.c",
        "src/cluster.h",
        "src/crc64.h",
        "src/defrag.c",
        "src/dict.h",
        "src/endianconv.h",
        "src/evict.c",
        "src/expire.c",
        "src/fmacros.h",
        "src/intset.h",
        "src/latency.h",
        "src/lazyfree.c",
        "src/listpack.c",
        "src/listpack.h",
        "src/listpack_malloc.h",
        "src/localtime.c",
        "src/lolwut.c",
        "src/lolwut.h",
        "src/lolwut5.c",
        "src/lolwut6.c",
        "src/module.c",
        "src/quicklist.h",
        "src/rdb.h",
        "src/redis-check-aof.c",
        "src/redismodule.h",
        "src/rio.h",
        "src/server.c",
        "src/server.h",
        "src/sha1.h",
        "src/siphash.c",
        "src/slowlog.h",
        "src/solarisfixes.h",
        "src/sparkline.h",
        "src/timeout.c",
        "src/t_stream.c",
        "src/util.h",
        "src/ziplist.h",
        "src/zipmap.h",
    ],
    copts = ZCALLOC_COPT,
    deps = [":redis_lib"],
    alwayslink = 1,
)

cc_library(
    name = "redis_benchmark",
    srcs = ["src/redis-benchmark.c"],
    copts = ZCALLOC_COPT,
    deps = [":redis_lib"],
)

cc_library(
    name = "redis_cli",
    srcs = [
        "deps/linenoise/linenoise.h",
        "src/help.h",
        "src/redis-cli.c",
    ],
    copts = [
        "-std=c99",
        # This is required to include strncasecmp and strcasecmp declaration.
        "-D_DEFAULT_SOURCE",
    ] + ZCALLOC_COPT,
    deps = [
        ":hiredis_lib",
        ":redis_lib",
    ],
)

cc_binary(
    name = "redis_cli_bin",
    deps = [":redis_cli"],
)

cc_library(
    name = "redis_check_aof",
    srcs = ["src/redis-check-aof.c"],
    deps = [":redis_lib"],
)
