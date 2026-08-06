## 编译

ndk方式编译，无需Android Studio参与，从而支持批量自动化处理

参考： https://android-review.googlesource.com/c/platform/ndk/+/1127433

编译命令：

ndk-build.cmd APP_BUILD_SCRIPT=./Android.mk APP_ALLOW_MISSING_DEPS=true  NDK_APPLICATION_MK=./Application.mk NDK_PROJECT_PATH=.

## 使用
