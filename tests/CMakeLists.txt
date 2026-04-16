# ==============================================================================
# wekey-skf Tests CMakeLists.txt
# ==============================================================================

add_executable(cert_service_test
    core/crypto/CertServiceTest.cpp
)

target_include_directories(cert_service_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(cert_service_test PRIVATE
    Qt6::Core
    Qt6::Test
    wekey_core_crypto
    wekey_log
    wekey_plugin
)

add_test(NAME cert_service_test COMMAND cert_service_test)

add_executable(enc_dec_dialog_test
    gui/dialogs/EncDecTestDialogTest.cpp
)

target_include_directories(enc_dec_dialog_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(enc_dec_dialog_test PRIVATE
    Qt6::Core
    Qt6::Test
    Qt6::Widgets
    wekey_gui
)

target_compile_options(enc_dec_dialog_test PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-extra-semi>
)

add_test(NAME enc_dec_dialog_test COMMAND enc_dec_dialog_test)

add_executable(app_detail_view_test
    gui/views/AppDetailViewTest.cpp
)

target_include_directories(app_detail_view_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(app_detail_view_test PRIVATE
    Qt6::Core
    Qt6::Test
    Qt6::Widgets
    wekey_gui
)

target_compile_options(app_detail_view_test PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-extra-semi>
)

add_test(NAME app_detail_view_test COMMAND app_detail_view_test)

add_executable(add_module_dialog_test
    gui/dialogs/AddModuleDialogTest.cpp
)

target_include_directories(add_module_dialog_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(add_module_dialog_test PRIVATE
    Qt6::Core
    Qt6::Test
    Qt6::Widgets
    wekey_gui
)

target_compile_options(add_module_dialog_test PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-extra-semi>
)

add_test(NAME add_module_dialog_test COMMAND add_module_dialog_test)

find_program(BASH_EXECUTABLE bash REQUIRED)

# Shell 级回归测试：验证脚本里的选库 / 架构检查逻辑，
# 避免必须真正打包一次才能发现映射或校验规则被改坏。
add_test(
    NAME mac_skf_lib_selector_test
    COMMAND ${BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/package/mac_skf_lib_selector_test.sh
            ${CMAKE_SOURCE_DIR}
)

add_test(
    NAME mac_mach_arch_inspector_test
    COMMAND ${BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/package/mac_mach_arch_inspector_test.sh
            ${CMAKE_SOURCE_DIR}
)
