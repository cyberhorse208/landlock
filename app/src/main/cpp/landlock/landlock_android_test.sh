#!/system/bin/sh
#=============================================================================
# Landlock Android 一键测试脚本
# 环境：Android 16+, kernel 6.12+
# 工作目录：/data/local/tmp/landlock
# 需要 root 权限
#=============================================================================

set -u

#=============================================================================
# 配置
#=============================================================================
WORK_DIR="/data/local/tmp/landlock/"
WORK_FILE_DIR="/data/local/tmp/landlock/files"
WORK_EXE_DIR="/data/local/tmp/landlock/execute"
SANDBOXER="${WORK_EXE_DIR}/sandboxer"
SANDBOXER_TEST="${WORK_EXE_DIR}/sandboxer-test"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="${WORK_DIR}/test_result_${TIMESTAMP}.log"
PASSED=0
FAILED=0
SKIPPED=0

# 颜色定义（ANSI）
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

#=============================================================================
# 工具函数
#=============================================================================

log() {
    local msg="$*"
    printf "%s\n" "${msg}" | tee -a "${LOGFILE}"
}

log_color() {
    local color="$1"
    shift
    local msg="$*"
    printf "${color}%s${NC}\n" "${msg}" | tee -a "${LOGFILE}"
}

log_separator() {
    local title="$1"
    local line="============================================================"
    printf "\n${CYAN}%s${NC}\n" "${line}" | tee -a "${LOGFILE}"
    printf "${CYAN}  %s${NC}\n" "${title}" | tee -a "${LOGFILE}"
    printf "${CYAN}%s${NC}\n" "${line}" | tee -a "${LOGFILE}"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_color "${RED}" "[ERROR] 此脚本需要 root 权限运行！"
        exit 1
    fi
}

check_landlock() {
    if ! dmesg 2>/dev/null | grep -q "landlock: Up and running"; then
        log_color "${YELLOW}" "[WARN] 未检测到 landlock: Up and running，Landlock 可能未加载"
        log_color "${YELLOW}" "       继续执行测试，但可能全部失败"
    else
        log_color "${GREEN}" "[OK] Landlock LSM 已加载"
    fi
}

check_landlock_config() {
    local config_found=0
    local config_val=""

    # 方式1：/proc/config.gz（需要 CONFIG_IKCONFIG_PROC=y）
    if [ -f /proc/config.gz ]; then
        config_val=$(zcat /proc/config.gz 2>/dev/null | grep "^CONFIG_SECURITY_LANDLOCK")
        if [ -n "${config_val}" ]; then
            config_found=1
        fi
    fi

    # 方式2：/proc/config（部分内核直接暴露明文）
    if [ "${config_found}" -eq 0 ] && [ -f /proc/config ]; then
        config_val=$(grep "^CONFIG_SECURITY_LANDLOCK" /proc/config 2>/dev/null)
        if [ -n "${config_val}" ]; then
            config_found=1
        fi
    fi

    # 方式3：系统分区内核配置文件
    local cfg
    for cfg in /system/kernel/config.gz /vendor/kernel/config.gz; do
        if [ "${config_found}" -eq 0 ] && [ -f "${cfg}" ]; then
            config_val=$(zcat "${cfg}" 2>/dev/null | grep "^CONFIG_SECURITY_LANDLOCK")
            if [ -n "${config_val}" ]; then
                config_found=1
                break
            fi
        fi
    done

    if [ "${config_found}" -eq 0 ]; then
        log_color "${YELLOW}" "[WARN] 无法读取内核编译配置（/proc/config.gz 不可用），跳过 CONFIG_SECURITY_LANDLOCK 检查"
        return
    fi

    if printf "%s" "${config_val}" | grep -q "^CONFIG_SECURITY_LANDLOCK=y"; then
        log_color "${GREEN}" "[OK] CONFIG_SECURITY_LANDLOCK=y 已设置（${config_val}）"
    elif printf "%s" "${config_val}" | grep -q "^CONFIG_SECURITY_LANDLOCK"; then
        log_color "${RED}" "[ERROR] CONFIG_SECURITY_LANDLOCK 未设为 y：${config_val}"
        log_color "${RED}" "        Landlock 沙箱无法工作，请重新编译内核并设置 CONFIG_SECURITY_LANDLOCK=y"
    else
        log_color "${RED}" "[ERROR] CONFIG_SECURITY_LANDLOCK 未在内核配置中找到"
        log_color "${RED}" "        请重新编译内核并设置 CONFIG_SECURITY_LANDLOCK=y"
    fi
}

check_tools() {
    local missing=0
    if [ ! -x "${SANDBOXER}" ]; then
        log_color "${RED}" "[ERROR] 找不到 sandboxer: ${SANDBOXER}"
        missing=1
    else
        log_color "${GREEN}" "[OK] sandboxer: ${SANDBOXER}"
    fi

    if [ ! -x "${SANDBOXER_TEST}" ]; then
        log_color "${RED}" "[ERROR] 找不到 sandboxer-test: ${SANDBOXER_TEST}"
        missing=1
    else
        log_color "${GREEN}" "[OK] sandboxer-test: ${SANDBOXER_TEST}"
    fi

    if [ "${missing}" -eq 1 ]; then
        exit 1
    fi
}

prepare_test_files() {
    log ""
    log_color "${BLUE}" ">>> 准备测试文件..."

    # 创建工作目录结构
    mkdir -p "${WORK_EXE_DIR}" 2>/dev/null
    mkdir -p "${WORK_FILE_DIR}/ro" 2>/dev/null
    mkdir -p "${WORK_FILE_DIR}/rw" 2>/dev/null
    mkdir -p "${WORK_FILE_DIR}/rw-bak" 2>/dev/null

    # 创建测试用读文件
    if [ ! -f "${WORK_FILE_DIR}/ro/readme.txt" ]; then
        echo "hello world" > "${WORK_FILE_DIR}/ro/readme.txt"
        log "  [创建] ${WORK_FILE_DIR}/ro/readme.txt"
    else
        log "  [已存在] ${WORK_FILE_DIR}/ro/readme.txt"
    fi

    # 创建 /data/media/0/Download/hello.txt
    mkdir -p /data/media/0/Download 2>/dev/null
    if [ ! -f /data/media/0/Download/hello.txt ]; then
        echo "hello world" > /data/media/0/Download/hello.txt
        log "  [创建] /data/media/0/Download/hello.txt"
    else
        log "  [已存在] /data/media/0/Download/hello.txt"
    fi

    # 探测 Android/data 测试文件
    local pkg_dir="/data/media/0/Android/data/com.vivo.landlocktest/files"
    if [ ! -f "${pkg_dir}/message.txt" ]; then
        echo "just make sure file path exist!!" > "${pkg_dir}/message.txt"
        log "  [不存在] ${pkg_dir}/message.txt"
    else
        log "  [已存在] ${pkg_dir}/message.txt"
    fi

    # 确保 writeme.txt 可被写入
    touch "${WORK_FILE_DIR}/rw/writeme.txt" 2>/dev/null
    chmod 666 "${WORK_FILE_DIR}/rw/writeme.txt" 2>/dev/null

    log_color "${GREEN}" "  [OK] 测试文件准备完成"
}

# 断言：检查输出中是否包含指定字符串
assert_contains() {
    local desc="$1"
    local output="$2"
    local pattern="$3"
    local expect="$4"  # "pass" 表示期望包含, "fail" 表示期望不包含

    if [ "${expect}" = "pass" ]; then
        if printf "%s" "${output}" | grep -q "${pattern}"; then
            printf "  ${GREEN}[PASS]${NC} %s\n" "${desc}"
            return 0
        else
            printf "  ${RED}[FAIL]${NC} %s (期望包含: '%s')\n" "${desc}" "${pattern}"
            return 1
        fi
    else
        if printf "%s" "${output}" | grep -q "${pattern}"; then
            printf "  ${RED}[FAIL]${NC} %s (不应包含: '%s')\n" "${desc}" "${pattern}"
            return 1
        else
            printf "  ${GREEN}[PASS]${NC} %s\n" "${desc}"
            return 0
        fi
    fi
}

# 运行单个测试
run_test() {
    local test_id="$1"
    local test_name="$2"
    local cmd="$3"
    shift 3
    # 剩余参数是断言规则: "desc|pattern|expect" 三元组

    log_separator "${test_id}: ${test_name}"
    log_color "${MAGENTA}" "命令: ${cmd}"

    local output
    local ret=0
    output=$(eval "${cmd}" 2>&1) || ret=$?

    # 打印输出（截断过长内容）
    if [ ${#output} -gt 2000 ]; then
        printf "%s\n" "${output}" | head -30 | tee -a "${LOGFILE}"
        log "  ... (输出过长，已截断，完整内容见日志文件)"
    else
        printf "%s\n" "${output}" | tee -a "${LOGFILE}"
    fi

    local test_passed=0
    local test_failed=0
    local assertions="$#"
    local i=1
    while [ $# -ge 3 ]; do
        local a_desc="$1"
        local a_pattern="$2"
        local a_expect="$3"
        shift 3

        if assert_contains "${a_desc}" "${output}" "${a_pattern}" "${a_expect}"; then
            test_passed=$((test_passed + 1))
        else
            test_failed=$((test_failed + 1))
        fi
    done

    if [ "${test_failed}" -eq 0 ]; then
        log_color "${GREEN}" "  >>> 测试结果: PASS (${test_passed}/${assertions})"
        PASSED=$((PASSED + 1))
    else
        log_color "${RED}" "  >>> 测试结果: FAIL (通过 ${test_passed}, 失败 ${test_failed})"
        FAILED=$((FAILED + 1))
    fi
}

# 拼接 sandboxer 命令
# 用法: make_cmd <RO路径> <RW路径> [-v] -r <读文件> -w <写文件>
make_cmd() {
    local ro="$1"
    local rw="$2"
    shift 2
    local cmd
    cmd="LL_FS_RO=\"${ro}\""
    cmd="${cmd} LL_FS_RW=\"${rw}\""
    cmd="${cmd} LL_FORCE_LOG=1 ${SANDBOXER}"
    cmd="${cmd} -p ${SANDBOXER_TEST}"
    cmd="${cmd} $*"
    printf "%s" "${cmd}"
}

#=============================================================================
# 主流程
#=============================================================================

main() {
    # 初始化日志
    echo "" > "${LOGFILE}"
    log "Landlock Android 测试脚本"
    log "运行时间: $(date)"
    log "内核版本: $(uname -r 2>/dev/null || echo 'unknown')"
    log "日志文件: ${LOGFILE}"
    log ""

    # 环境检查
    log_separator "环境检查"
    check_root
    check_landlock
    check_landlock_config
    check_tools
    prepare_test_files

    # 切换到工作目录
    cd "${WORK_DIR}" || {
        log_color "${RED}" "[ERROR] 无法进入工作目录: ${WORK_DIR}"
        exit 1
    }

    #-------------------------------------------------------------------------
    # 公共路径变量
    #   命名规则：目录用 _DIR 后缀，文件用 _FILE 后缀
    #-------------------------------------------------------------------------
    local BASE_RO_DIR="/apex/:/linkerconfig:${WORK_EXE_DIR}"    # LL_FS_RO 公共前缀
    local RO_DIR="${WORK_FILE_DIR}/ro"                            # 非fuse 只读目录
    local RW_DIR="${WORK_FILE_DIR}/rw"                            # 非fuse 读写目录
    local RW_BAK_DIR="${WORK_FILE_DIR}/rw-bak"                   # 非fuse 备用读写目录（不含目标文件）

    local PKG="com.vivo.landlocktest"
    local DATA_PKG_DIR="/data/media/0/Android/data/${PKG}"      # fuse backing 包目录
    local STO_PKG_DIR="/storage/emulated/0/Android/data/${PKG}" # fuse 挂载包目录

    local DATA_DL_DIR="/data/media/0/Download"             # fuse Download backing 目录
    local STO_DL_DIR="/storage/emulated/0/Download"        # fuse Download 挂载目录

    local README_FILE="${RO_DIR}/readme.txt"
    local WRITEME_FILE="${RW_DIR}/writeme.txt"
    local DATA_MSG_FILE="${DATA_PKG_DIR}/files/message.txt"
    local STO_MSG_FILE="${STO_PKG_DIR}/files/message.txt"
    local DATA_WRITE_FILE="${DATA_PKG_DIR}/files/write.txt"
    local STO_WRITE_FILE="${STO_PKG_DIR}/files/write.txt"
    local DATA_HELLO_FILE="${DATA_DL_DIR}/hello.txt"
    local STO_HELLO_FILE="${STO_DL_DIR}/hello.txt"
    local DATA_DL_WRITE_FILE="${DATA_DL_DIR}/write.txt"
    local STO_DL_WRITE_FILE="${STO_DL_DIR}/write.txt"

    #=========================================================================
    # 测试组1：非fuse文件系统测试
    #=========================================================================
    log_separator "测试组1: 非fuse文件系统测试"

    local _cmd

    _cmd=$(make_cmd "${BASE_RO_DIR}:${RO_DIR}" "${RW_DIR}" \
        -r "${README_FILE}" -w "${WRITEME_FILE}")
    run_test \
        "T1.1" \
        "非fuse — 读写目录都包括" \
        "${_cmd}" \
        "读操作成功" "hello world" "pass" \
        "写操作成功" "hello world" "pass"

    _cmd=$(make_cmd "${BASE_RO_DIR}:${RO_DIR}" "${RW_BAK_DIR}" \
        -r "${README_FILE}" -w "${WRITEME_FILE}")
    run_test \
        "T1.2" \
        "非fuse — 读目录包括，写目录不包括" \
        "${_cmd}" \
        "读操作成功" "hello world" "pass" \
        "写操作被Landlock拒绝" "Permission denied" "pass"

    _cmd=$(make_cmd "${BASE_RO_DIR}" "${RW_DIR}" \
        -r "${README_FILE}" -w "${WRITEME_FILE}")
    run_test \
        "T1.3" \
        "非fuse — 读目录不包含，写目录包含" \
        "${_cmd}" \
        "读操作被Landlock拒绝" "Permission denied" "pass" \
        "写操作成功" "hello world" "pass"

    #=========================================================================
    # 测试组2：fuse文件系统测试 [Android/data路径]
    #=========================================================================
    log_separator "测试组2: fuse文件系统测试 [fuse-bpf /Storage/emulated/0/Android/data路径]"

    # 先显示 fuse 挂载信息
    log_color "${BLUE}" ">>> fuse 挂载信息:"
    mount 2>/dev/null | grep "/data " | tee -a "${LOGFILE}"
    mount 2>/dev/null | grep "/storage/emulated" | tee -a "${LOGFILE}"
    log ""

    _cmd=$(make_cmd "${BASE_RO_DIR}:${DATA_PKG_DIR}" "${DATA_PKG_DIR}" \
        -r "${DATA_MSG_FILE}" -w "${DATA_WRITE_FILE}")
    run_test \
        "T2.1" \
        "fuse-bpf Android/data — 规则：/data路径，读包含，写包含，操作： /data路径" \
        "${_cmd}" \
        "读操作成功" "just make sure" "pass" \
        "写操作成功" "hello world" "pass"

    _cmd=$(make_cmd "${BASE_RO_DIR}:${DATA_DL_DIR}" "${DATA_DL_DIR}" \
        -r "${DATA_MSG_FILE}" -w "${DATA_WRITE_FILE}")
    run_test \
        "T2.2" \
        "fuse-bpf Android/data — 规则：读写都不包含，操作： /data路径" \
        "${_cmd}" \
        "读操作被Landlock拒绝" "Permission denied" "pass" \
        "写操作被Landlock拒绝" "Permission denied" "pass"

    _cmd=$(make_cmd "${BASE_RO_DIR}:${DATA_PKG_DIR}" "${DATA_PKG_DIR}" \
        -r "${STO_MSG_FILE}" -w "${STO_WRITE_FILE}")
    run_test \
        "T2.3" \
        "fuse-bpf Android/data — 规则：/data路径，读包含，写包含， 操作：/storage路径" \
        "${_cmd}" \
        "读操作被Landlock拒绝" "Permission denied" "pass" \
        "写操作被Landlock拒绝" "Permission denied" "pass"

    # 测试特别说明
    # 原生ACK内核中，下面测试应该被landlock拒绝
    # 如果使用支持fuse-bpf backing file特性的landlock修改版本，那么不会被拒绝

    _cmd=$(make_cmd "${BASE_RO_DIR}:${STO_PKG_DIR}" "${STO_PKG_DIR}" \
        -r "${STO_MSG_FILE}" -w "${STO_WRITE_FILE}")
    echo 0 > /proc/sys/kernel/landlock/fuse_backing_check
    run_test \
        "T2.4" \
        "fuse-bpf Android/data — 规则：/storage路径，读包含，写包含，操作：/storage路径" \
        "${_cmd}" \
        "读操作被Landlock拒绝" "Permission denied" "pass" \
        "写操作被Landlock拒绝" "Permission denied" "pass"
    log_color "${YELLOW}" "请仔细检查T2.4的结果，是否FAIL/PASS正确，需要根据当前内核是否为修改版本（支持fuse-bpf backing file特性的landlock修改版本）來判斷"


    if echo 1 > /proc/sys/kernel/landlock/fuse_backing_check ; then
        log_color "${GREEN}" " echo 1 > /proc/sys/kernel/landlock/fuse_backing_check ，继续执行 T2.5"
        run_test \
            "T2.5" \
            "fuse-bpf Android/data — 规则：/storage路径，读包含，写包含，操作：/storage路径" \
            "${_cmd}" \
          "读操作成功" "just make sure" "pass" \
          "写操作成功" "hello world" "pass"
    else
        log_color "${YELLOW}" " echo 1 > /proc/sys/kernel/landlock/fuse_backing_check 失败，跳过 T2.5"
        SKIPPED=$((SKIPPED + 1))
    fi

    _cmd=$(make_cmd "${BASE_RO_DIR}:${STO_PKG_DIR}:${DATA_PKG_DIR}" "${STO_PKG_DIR}:${DATA_PKG_DIR}" \
            -r "${STO_MSG_FILE}" -w "${STO_WRITE_FILE}")
    run_test \
         "T2.6" \
         "fuse-bpf Android/data — 规则：/storage + /data 双重路径，读包含，写包含， 操作：/storage路径" \
         "${_cmd}" \
         "读操作成功" "just make sure" "pass" \
         "写操作成功" "hello world" "pass"

    #=========================================================================
    # 测试组3：fuse文件系统测试 [非Android/data路径]
    #=========================================================================
    log_separator "测试组3: fuse文件系统测试 [非fuse-bpf路径]"

    _cmd=$(make_cmd "${BASE_RO_DIR}:${DATA_PKG_DIR}" "${DATA_PKG_DIR}" \
        -r "${DATA_HELLO_FILE}" -w "${DATA_DL_WRITE_FILE}")
    run_test \
        "T3.1" \
        "fuse Download — /data/media路径，读写都不包含" \
        "${_cmd}" \
        "读操作被Landlock拒绝" "Permission denied" "pass"\
        "写操作被Landlock拒绝" "Permission denied" "pass"

    _cmd=$(make_cmd "${BASE_RO_DIR}:${STO_PKG_DIR}" "${STO_PKG_DIR}" \
        -r "${STO_HELLO_FILE}" -w "${STO_DL_WRITE_FILE}")
    run_test \
        "T3.2" \
        "fuse Download — /storage路径，读写都不包含" \
        "${_cmd}" \
        "读操作被Landlock拒绝" "Permission denied" "pass"\
        "写操作被Landlock拒绝" "Permission denied" "pass"

    _cmd=$(make_cmd "${BASE_RO_DIR}:${DATA_DL_DIR}" "${DATA_PKG_DIR}" \
        -r "${DATA_HELLO_FILE}" -w "${DATA_DL_WRITE_FILE}")
    run_test \
        "T3.3" \
        "fuse Download — /data/media路径，读包含，写不包含" \
        "${_cmd}" \
        "读操作成功" "hello world" "pass" \
        "写操作被Landlock拒绝" "Permission denied" "pass"

    _cmd=$(make_cmd "${BASE_RO_DIR}:${STO_DL_DIR}" "${DATA_PKG_DIR}" \
        -r "${STO_HELLO_FILE}" -w "${STO_DL_WRITE_FILE}")
    run_test \
        "T3.4" \
        "fuse Download — /storage路径，读包含，写不包含" \
        "${_cmd}" \
        "读操作成功" "hello world" "pass" \
        "写操作被Landlock拒绝" "Permission denied" "pass"

    #=========================================================================
    # 结果汇总
    #=========================================================================
    log_separator "结果汇总"
    local total=$((PASSED + FAILED + SKIPPED))
    printf "  总计: %d  通过: ${GREEN}%d${NC}  失败: ${RED}%d${NC}  跳过: ${YELLOW}%d${NC}\n" \
        "${total}" "${PASSED}" "${FAILED}" "${SKIPPED}" | tee -a "${LOGFILE}"
    log ""
    if [ "${FAILED}" -eq 0 ]; then
        log_color "${GREEN}" "  >>> 全部测试通过！"
    else
        log_color "${RED}" "  >>> 存在 ${FAILED} 个测试失败，请检查日志"
    fi
    log ""
    log "完整日志已保存到: ${LOGFILE}"
}

#=============================================================================
# 入口
#=============================================================================
main "$@"
