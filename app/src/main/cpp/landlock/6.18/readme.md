## 编译

编译命令：
D:\Users\11135250\AppData\Local\Android\Sdk\ndk\30.0.14904198\\ndk-build.cmd APP_BUILD_SCRIPT=./Android.mk APP_ALLOW_MISSING_DEPS=true NDK_APPLICATION_MK=./Application.mk NDK_PROJECT_PATH=.

**注意**

必须使用ndk-30及以上编译，否则会没有相关宏定义，报错(比如下面使用ndk 28)：

```
./sandboxer.c:361:36: error: use of undeclared identifier 'LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON'
  361 |     int supported_restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
      |                                    ^
./sandboxer.c:438:22: error: use of undeclared identifier 'LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON'
  438 |                     ~LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
      |                      ^
./sandboxer.c:484:15: error: use of undeclared identifier 'LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON'
  484 |               LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON)) {
      |               ^
./sandboxer.c:489:31: error: use of undeclared identifier 'LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON'
  489 |         set_restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
      |                               ^
4 errors generated.

```
