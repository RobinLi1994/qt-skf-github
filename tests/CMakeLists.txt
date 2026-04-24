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

add_executable(cert_detail_dialog_test
    gui/dialogs/CertDetailDialogTest.cpp
)

target_include_directories(cert_detail_dialog_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(cert_detail_dialog_test PRIVATE
    Qt6::Core
    Qt6::Test
    Qt6::Widgets
    wekey_gui
)

target_compile_options(cert_detail_dialog_test PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-extra-semi>
)

add_test(NAME cert_detail_dialog_test COMMAND cert_detail_dialog_test)

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

add_executable(skf_plugin_test
    plugin/skf/SkfPluginTest.cpp
)

target_include_directories(skf_plugin_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(skf_plugin_test PRIVATE
    Qt6::Core
    Qt6::Test
    wekey_plugin
)

add_test(NAME skf_plugin_test COMMAND skf_plugin_test)
