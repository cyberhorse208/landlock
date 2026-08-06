## 编译

"android-ndk-r28\ndk-build.cmd" APP_BUILD_SCRIPT=./Android.mk APP_ALLOW_MISSING_DEPS=true  NDK_APPLICATION_MK=./Application.mk NDK_PROJECT_PATH=.


**注意**

必须使用ndk-r28及以上编译，否则会没有相关宏定义，报错(比如下面使用ndk/25.2.9519653)：

```
PS D:\Users\11135250\StudioProjects\NativeTest\app\src\main\cpp\landlock\6.6> ndk-build.cmd APP_BUILD_SCRIPT=./Android.mk APP_ALLOW_MISSING_DEPS=true  NDK_APPLICATION_MK=./Application.mk NDK_PROJECT_PATH=.
[arm64-v8a] Compile        : sandboxer <= sandboxer.c
./sandboxer.c:131:35: error: use of undeclared identifier 'LANDLOCK_ACCESS_FS_TRUNCATE'
                        path_beneath.allowed_access &= ACCESS_FILE;
                                                       ^
./sandboxer.c:80:2: note: expanded from macro 'ACCESS_FILE'
        LANDLOCK_ACCESS_FS_TRUNCATE)
        ^
./sandboxer.c:181:48: error: use of undeclared identifier 'LANDLOCK_ACCESS_FS_REFER'
              access_fs_rw = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
                                                      ^
./sandboxer.c:168:2: note: expanded from macro 'ACCESS_FS_ROUGHLY_WRITE'
        LANDLOCK_ACCESS_FS_REFER | \
        ^
./sandboxer.c:181:48: error: use of undeclared identifier 'LANDLOCK_ACCESS_FS_TRUNCATE'
./sandboxer.c:169:2: note: expanded from macro 'ACCESS_FS_ROUGHLY_WRITE'
        LANDLOCK_ACCESS_FS_TRUNCATE)
        ^
./sandboxer.c:257:38: error: use of undeclared identifier 'LANDLOCK_ACCESS_FS_REFER'
                ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
                                                   ^
./sandboxer.c:261:38: error: use of undeclared identifier 'LANDLOCK_ACCESS_FS_TRUNCATE'
                ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
```

##
