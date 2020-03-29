
file(GLOB SOURCES 
	${CMAKE_CURRENT_SOURCE_DIR}/*.c*)

add_executable(pkcs11_test
	${SOURCES}
)

find_package(OpenSSL REQUIRED)
target_link_libraries(pkcs11_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

find_package(pthread)
target_link_libraries(pkcs11_test PRIVATE ${PTHREAD_LIBRARY})


if(MSVC)
	foreach(ROOTDIR ${CMAKE_PREFIX_PATH})
		file(GLOB RESOURCELIST ${ROOTDIR}/bin/*.dll)

		foreach(RESOURCE ${RESOURCELIST})
			add_custom_command(TARGET pkcs11_test POST_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${RESOURCE}
				$<TARGET_FILE_DIR:pkcs11_test>)
		endforeach()
	endforeach()
else()

endif()

